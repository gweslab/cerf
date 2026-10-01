#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "imx51_ccm.h"
#include "imx51_id.h"
#include "imx51_power_gate_line.h"

#include <array>
#include <cstdint>
#include <iterator>

namespace {

/* MCIMX51RM Table 34-1 memory map. */
constexpr uint32_t kBase = 0x73FD8000u;
constexpr uint32_t kSize = 0x00001000u;

constexpr uint32_t kGeneralEnd = 0x014u;

struct GpcReset { uint32_t off; uint32_t val; };
constexpr GpcReset kResets[] = {
    {0x000u, 0x02108000u},
    {0x004u, 0x00000000u},
    {0x008u, 0x00000001u},
    {0x00Cu, 0x00000700u},
    {0x010u, 0x00000030u},
};

/* sync_2 cspddk.dll: sub_C09C499C maps GPC +0x200 to dword_C09C6104, the PGC that sub_C09C4EFC
   selects for gating signal 0x67 (gpu2d). */
constexpr uint32_t kPgcGpu2d    = 0x200u;
constexpr uint32_t kPgcIpu      = 0x220u;
constexpr uint32_t kPgcVpu      = 0x240u;
constexpr uint32_t kPgcGpu      = 0x260u;
constexpr uint32_t kSrpgNeon    = 0x280u;
constexpr uint32_t kSrpgArm     = 0x2A0u;
constexpr uint32_t kSrpgMegamix = 0x2E0u;
constexpr uint32_t kSrpgEmi     = 0x300u;

constexpr uint32_t kControlRegs[] = {kPgcGpu2d, kPgcIpu,  kPgcVpu,      kPgcGpu,
                                     kSrpgNeon, kSrpgArm, kSrpgMegamix, kSrpgEmi};
constexpr uint32_t kPcr = 1u << 0;

/* MCIMX51RM Table 7-26 CLPCR LPM: 00 run, 01 wait, 10 STOP, 11 LPSR. */
constexpr uint32_t kLpmRun  = 0u;
constexpr uint32_t kLpmWait = 1u;
constexpr uint32_t kLpmStop = 2u;

constexpr uint32_t kSequenceRegs[] = {0x284u, 0x288u, 0x2A4u, 0x2A8u};

/* Linux i.MX5 PM model: EMPGC0/1 at +0x2C0/+0x2D0. MCIMX51RM Table 28-4..28-7: EMPGCR
   PCR [0] reset 0, PUPSCR PUP[7:0] reset 1, PDNSCR PDN[7:0] reset 1, EMPGSR PSR w1c. */
constexpr uint32_t kEmpgcBases[]  = {0x2C0u, 0x2D0u};
constexpr uint32_t kEmpgcMasks[]  = {0x00000001u, 0x000000FFu, 0x000000FFu};
constexpr uint32_t kEmpgcResets[] = {0x00000000u, 0x00000001u, 0x00000001u};
constexpr uint32_t kEmpgcWords    = 3u;

template <size_t N>
int IndexOf(const uint32_t (&table)[N], uint32_t off) {
    for (size_t i = 0; i < N; ++i) {
        if (table[i] == off) return static_cast<int>(i);
    }
    return -1;
}

class Imx51Gpc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == SocId::Imx51;
    }

    void OnReady() override {
        ccm_   = &emu_.Get<Imx51Ccm>();
        gates_ = &emu_.Get<Imx51PowerGateLine>();
        ResetRegisters();
        emu_.Get<GuestCycleClock>().RegisterIdleListener([this] { OnIdle(); });
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            ResetRegisters();
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        if ((off & 0x3u) == 0u && off < kGeneralEnd) return general_[off >> 2];
        if (const int c = IndexOf(kControlRegs, off); c >= 0) return control_[c];
        if (const int e = EmpgcSlot(off); e >= 0) return empgc_[e];
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - kBase;
        if (const int c = IndexOf(kControlRegs, off); c >= 0) {
            control_[c] = value;
            return;
        }
        if (const int s = IndexOf(kSequenceRegs, off); s >= 0) {
            sequence_[s] = value;
            return;
        }
        if (const int e = EmpgcSlot(off); e >= 0) {
            empgc_[e] = value & kEmpgcMasks[e % kEmpgcWords];
            return;
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

    void SaveState(StateWriter& w) override {
        w.WriteBytes("general", general_.data(), sizeof(general_));
        w.WriteBytes("control", control_.data(), sizeof(control_));
        w.WriteBytes("sequence", sequence_.data(), sizeof(sequence_));
        w.WriteBytes("empgc", empgc_.data(), sizeof(empgc_));
    }

    void RestoreState(StateReader& r) override {
        r.ReadBytes("general", general_.data(), sizeof(general_));
        r.ReadBytes("control", control_.data(), sizeof(control_));
        r.ReadBytes("sequence", sequence_.data(), sizeof(sequence_));
        r.ReadBytes("empgc", empgc_.data(), sizeof(empgc_));
    }

private:
    static int EmpgcSlot(uint32_t off) {
        for (size_t b = 0; b < std::size(kEmpgcBases); ++b) {
            const uint32_t rel = off - kEmpgcBases[b];
            if (rel < kEmpgcWords * 4u && (rel & 0x3u) == 0u) {
                return static_cast<int>(b * kEmpgcWords + (rel >> 2));
            }
        }
        return -1;
    }

    /* MCIMX51RM §11.1.2, §11.2.1. */
    void OnIdle() {
        const uint32_t lpm = ccm_->WfiLowPowerMode();
        if (lpm == kLpmRun) return;
        if (lpm != kLpmWait && lpm != kLpmStop) {
            emu_.Get<Fatal>().Die("Imx51Gpc: WFI enters CLPCR LPM %u; its power gating is not "
                                  "modeled", lpm);
        }
        GateOnPcr(kPgcVpu, Imx51PowerGatedBlock::kVpu);
        GateOnPcr(kPgcGpu, Imx51PowerGatedBlock::kGpu3d);
        GateOnPcr(kPgcGpu2d, Imx51PowerGatedBlock::kGpu2d);
    }

    void GateOnPcr(uint32_t off, Imx51PowerGatedBlock block) {
        if ((control_[IndexOf(kControlRegs, off)] & kPcr) != 0u) gates_->PowerDown(block);
    }

    /* MCIMX51RM Table 54-10: system_rst_b resets the functional modules on every
       reset type. */
    void ResetRegisters() {
        for (const auto& r : kResets) general_[r.off >> 2] = r.val;
        control_.fill(0u);
        sequence_.fill(0u);
        for (size_t i = 0; i < empgc_.size(); ++i) empgc_[i] = kEmpgcResets[i % kEmpgcWords];
    }

    Imx51Ccm*           ccm_   = nullptr;
    Imx51PowerGateLine* gates_ = nullptr;

    std::array<uint32_t, kGeneralEnd / 4>                          general_{};
    std::array<uint32_t, std::size(kControlRegs)>                  control_{};
    std::array<uint32_t, std::size(kSequenceRegs)>                 sequence_{};
    std::array<uint32_t, std::size(kEmpgcBases) * kEmpgcWords>     empgc_{};
};

}

REGISTER_SERVICE(Imx51Gpc);
