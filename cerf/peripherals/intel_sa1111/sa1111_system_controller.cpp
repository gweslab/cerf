#include "sa1111_system_controller.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "../../state/state_stream.h"
#include "sa1111_sbi.h"

#include <algorithm>
#include <iterator>

namespace {

/* SA-1111 Developer's Manual §7.2.3: "the PLL 144-MHz (143.7696 MHz) clock is generated
   using 3.6864-MHz input clock". */
constexpr uint64_t kPllInputHz = 3686400u;

/* §5.2.2 SKCDR FBDiv reset 1001100; §5.2.3 SKAUD ACDiv reset 0011000; §5.2.1 SKPCR "All
   bits are cleared by reset"; §5.2.4 PMCDiv and §5.2.5 PTCDiv reset 00010001. */
constexpr uint32_t kResetRegs[9] = {0u, 0x4Cu, 0x18u, 0x11u, 0x11u};

/* Table 3-3 note 1: "All reserved bits are read back as zero." §5.2.1-§5.2.9: SKPCR 8:0,
   SKCDR 14:0, SKAUD 6:0, SKPMC 7:0, SKPTC 7:0, SKPEN0 0, SKPWM0 7:0, SKPEN1 0, SKPWM1 7:0. */
constexpr uint32_t kDefinedBits[9] = {0x1FFu, 0x7FFFu, 0x7Fu, 0xFFu, 0xFFu,
                                      0x1u,   0xFFu,   0x1u,  0xFFu};

struct PllSetting {
    uint64_t vco_num;
    uint64_t vco_den;
    uint64_t op_divide;
};

/* §5.2.2 SKCDR: "VCO output = VCO input * (FBDiv/IPDiv). Program FBDiv and IPDiv with
   (required value minus 2)", OPDiv 00 = VCO, 01 = /4, 10 = /2, 11 = /8. */
PllSetting DecodeSkcdr(uint32_t skcdr) {
    static constexpr uint64_t kOpDivide[4] = {1u, 4u, 2u, 8u};
    return {kPllInputHz * ((skcdr & 0x7Fu) + 2u), ((skcdr >> 7) & 0x1Fu) + 2u,
            kOpDivide[(skcdr >> 12) & 0x3u]};
}

}

bool Sa1111SystemController::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Jornada720;
}

void Sa1111SystemController::OnUnitReady() { LoadResetValues(); }

void Sa1111SystemController::OnChipReset(bool held) {
    if (held) LoadResetValues();
}

void Sa1111SystemController::LoadResetValues() {
    std::copy(std::begin(kResetRegs), std::end(kResetRegs), regs_);
}

uint32_t Sa1111SystemController::UnitReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off <= 0x20u && (off & 3u) == 0) return regs_[off >> 2];
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Sa1111SystemController::UnitWriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off <= 0x20u && (off & 3u) == 0) {
        regs_[off >> 2] = value & kDefinedBits[off >> 2];
        if (off <= 0x08u) NotifyClockListeners();
        return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Sa1111SystemController::RegisterClockListener(std::function<void()> fn) {
    clock_listeners_.push_back(std::move(fn));
}

void Sa1111SystemController::NotifyClockListeners() {
    for (auto& fn : clock_listeners_) fn();
}

void Sa1111SystemController::PllOutputRate(uint64_t& num, uint64_t& den) const {
    const PllSetting pll = DecodeSkcdr(regs_[1]);
    num = pll.vco_num;
    den = pll.vco_den * pll.op_divide;
}

/* §5.2.2 (printed 5-3): FBDiv "Set to 0x4c for VCO frequency of 144 MHz", OPDiv "Set to 0 for
   PLL frequency of 144 MHz"; §2.2 (printed 2-3): "Several dividers following the VCO signal
   create lower-frequency clocks". */
bool Sa1111SystemController::PllAtResetRate() const {
    const PllSetting now   = DecodeSkcdr(regs_[1]);
    const PllSetting reset = DecodeSkcdr(kResetRegs[1]);
    return now.vco_num * reset.vco_den == reset.vco_num * now.vco_den &&
           now.op_divide == reset.op_divide;
}

bool Sa1111SystemController::PllRunningAtResetRate() const {
    return emu_.Get<Sa1111Sbi>().PllClockRunning() && PllAtResetRate();
}

/* §5.2.3 SKAUD ACDiv "Program (required value -1)"; §7.3.2.2 SYS_CLK "is always 256 times
   the audio sampling frequency". */
void Sa1111SystemController::AudioFrameRate(uint64_t& num, uint64_t& den) const {
    PllOutputRate(num, den);
    den *= 256u * ((regs_[2] & 0x7Fu) + 1u);
}

void Sa1111SystemController::SaveState(StateWriter& w) {
    w.WriteBytes("regs", regs_, sizeof(regs_));
}

void Sa1111SystemController::RestoreState(StateReader& r) {
    r.ReadBytes("regs", regs_, sizeof(regs_));
}

REGISTER_SERVICE(Sa1111SystemController);
