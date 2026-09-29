#include "pxa255_memory_controller.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../boards/board_context.h"
#include "pxa255_clock_manager.h"
#include "pxa255_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

namespace {

/* Table 6-5 sheets 1-2 (printed 6-15, 6-16): K2FREE bit 25, APD bit 20, K2DB2 bit 19,
   K2RUN bit 18. */
constexpr uint32_t kK2Free = 1u << 25;
constexpr uint32_t kApd    = 1u << 20;
constexpr uint32_t kK2Db2  = 1u << 19;
constexpr uint32_t kK2Run  = 1u << 18;

struct RegisterReset {
    uint32_t off;
    uint32_t value;
};

/* Table 6-43 registers: Table 6-2 MDCNFG, Figure 6-33 MDREFR (asynchronous boot), Table 6-24
   MSC0-2, Table 6-30 MECR, Tables 6-13 / 6-16 SXCNFG / SXMRS, Tables 6-26 to 6-28, Table 6-3
   MDMRS, Table 6-4 MDMRSLP. */
constexpr RegisterReset kResets[] = {
    {0x00u, 0x00000000u}, {0x04u, 0x03CA4FFFu}, {0x08u, 0x7FF07FF0u}, {0x0Cu, 0x7FF07FF0u},
    {0x10u, 0x7FF07FF0u}, {0x14u, 0x00000000u}, {0x1Cu, 0x00000004u}, {0x24u, 0x02320232u},
    {0x28u, 0x00000000u}, {0x2Cu, 0x00000000u}, {0x30u, 0x00000000u}, {0x34u, 0x00000000u},
    {0x38u, 0x00000000u}, {0x3Cu, 0x00000000u}, {0x40u, 0x00220022u}, {0x58u, 0x00000000u},
};

bool IsResetRegister(uint32_t off) {
    for (const RegisterReset& r : kResets) {
        if (r.off == off) return true;
    }
    return false;
}

}  // namespace

bool Pxa255MemoryController::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Pxa255;
}

void Pxa255MemoryController::OnReady() {
    ResetRegisters();
    auto& reset = emu_.Get<GuestCpuReset>();
    reset.RegisterResetListener([this](ResetLineKind kind) { OnResetLine(kind); });
    reset.RegisterResetReleaseListener([this] { PublishSdclk2(); });
    emu_.Get<Pxa255ClockManager>().RegisterMemoryClockListener([this] { PublishSdclk2(); });
    emu_.Get<PeripheralDispatcher>().Register(this);
}

/* §6.11 (printed 6-79): hardware, watchdog and sleep reset; §6.12 (printed 6-81): "On a
   GPIO Reset, the Memory Controller registers keep the values they had before the reset." */
void Pxa255MemoryController::OnResetLine(ResetLineKind kind) {
    if (kind == ResetLineKind::Other && !emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) {
        return;
    }
    ResetRegisters();
}

void Pxa255MemoryController::ResetRegisters() {
    for (const RegisterReset& r : kResets) regs_[r.off / 4u] = r.value;
}

/* Table 6-5: K2FREE "SDCLK2 is free-running (ignores MDREFR[APD] or MDREFR[K2RUN] bits)";
   K2RUN "SDCLK2 enabled"; K2DB2 "SDCLK2 runs at one-half the MEMCLK frequency". */
uint64_t Pxa255MemoryController::Sdclk2Hz() const {
    const uint32_t mdrefr = regs_[kMdrefr / 4u];
    if ((mdrefr & kK2Free) == 0u) {
        if ((mdrefr & kK2Run) == 0u) return 0u;
        if ((mdrefr & kApd) != 0u) {
            emu_.Get<Fatal>().Die("Pxa255MemoryController: SDCLK2 auto-power-down "
                                  "(MDREFR 0x%08X) is not modelled", mdrefr);
        }
    }
    const uint64_t memclk = emu_.Get<Pxa255ClockManager>().MemoryClockHz();
    return (mdrefr & kK2Db2) != 0u ? memclk / 2u : memclk;
}

void Pxa255MemoryController::RegisterSdclk2Listener(std::function<void()> fn) {
    published_sdclk2_hz_ = Sdclk2Hz();
    sdclk2_listeners_.push_back(std::move(fn));
}

void Pxa255MemoryController::PublishSdclk2() {
    if (sdclk2_listeners_.empty()) return;
    const uint64_t hz = Sdclk2Hz();
    if (hz == published_sdclk2_hz_) return;
    published_sdclk2_hz_ = hz;
    for (auto& fn : sdclk2_listeners_) fn();
}

uint32_t Pxa255MemoryController::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    /* Table 6-43: BOOT_DEF "Read-Only Boot-time register. Contains BOOT_SEL and PKG_SEL
       values." */
    if (off == kBootDef) HaltUnsupportedAccess("ReadWord(BOOT_DEF strap)", addr, 0);
    if (IsResetRegister(off)) return regs_[off / 4u];
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa255MemoryController::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off == kBootDef) HaltUnsupportedAccess("WriteWord(BOOT_DEF read-only)", addr, value);
    if (IsResetRegister(off)) {
        regs_[off / 4u] = value;
        if (off == kMdrefr) PublishSdclk2();
        return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Pxa255MemoryController::SaveState(StateWriter& w) {
    w.WriteBytes("regs", regs_, sizeof(regs_));
}

void Pxa255MemoryController::RestoreState(StateReader& r) {
    r.ReadBytes("regs", regs_, sizeof(regs_));
}

REGISTER_SERVICE(Pxa255MemoryController);
