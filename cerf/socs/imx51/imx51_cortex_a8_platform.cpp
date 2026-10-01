#include "imx51_cortex_a8_platform.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "imx51_id.h"

#include <cstdint>

namespace {

/* MCIMX51RM Table 14-1. */
constexpr uint32_t kOffLpc  = 0x00Cu;
constexpr uint32_t kOffIcgc = 0x014u;
constexpr uint32_t kOffAmc  = 0x018u;

/* MCIMX51RM Table 14-6. */
constexpr uint32_t kLpcDsm      = 1u << 0;
constexpr uint32_t kLpcWritable = 0x00000003u;

/* MCIMX51RM Figure 14-8 / Table 14-8: DT_PRLD, ACLK_PRLD and IPG_PRLD read 0. */
constexpr uint32_t kIcgcDividers = 0x00000777u;
constexpr uint32_t kIcgcPreloads = 0x00000888u;
constexpr uint32_t kIcgcReset    = 0x00000777u;

/* MCIMX51RM Figure 14-9 / Table 14-9. */
constexpr uint32_t kAmcWritable = 0x0000000Fu;
constexpr uint32_t kAmcReset    = 0x00000003u;

}

REGISTER_SERVICE(Imx51CortexA8Platform);

bool Imx51CortexA8Platform::ShouldRegister() {
    return emu_.Get<BoardContext>().GetSocId() == SocId::Imx51;
}

void Imx51CortexA8Platform::OnReady() {
    ResetRegisters();
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        ResetRegisters();
    });
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void Imx51CortexA8Platform::ResetRegisters() {
    lpc_  = 0u;
    icgc_ = kIcgcReset;
    amc_  = kAmcReset;
}

uint32_t Imx51CortexA8Platform::ReadWord(uint32_t addr) {
    switch (addr - MmioBase()) {
        case kOffLpc:  return lpc_;
        case kOffIcgc: return icgc_;
        case kOffAmc:  return amc_;
        default:       break;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Imx51CortexA8Platform::WriteWord(uint32_t addr, uint32_t value) {
    switch (addr - MmioBase()) {
        case kOffLpc:
            if ((value & ~kLpcWritable) == 0u) {
                lpc_ = value;
                return;
            }
            break;
        case kOffIcgc:
            if ((value & ~(kIcgcDividers | kIcgcPreloads)) == 0u) {
                icgc_ = value & kIcgcDividers;
                return;
            }
            break;
        case kOffAmc:
            if ((value & ~kAmcWritable) == 0u) {
                amc_ = value;
                return;
            }
            break;
        default:
            break;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

/* MCIMX51RM 14.4.3.4 / Table 14-6: DSM gates the platform dsm_request. */
bool Imx51CortexA8Platform::DeepSleepRequestEnabled() const {
    return (lpc_ & kLpcDsm) != 0u;
}

void Imx51CortexA8Platform::SaveState(StateWriter& w) {
    w.Write("lpc", lpc_);
    w.Write("icgc", icgc_);
    w.Write("amc", amc_);
}

void Imx51CortexA8Platform::RestoreState(StateReader& r) {
    r.Read("lpc", lpc_);
    r.Read("icgc", icgc_);
    r.Read("amc", amc_);
}
