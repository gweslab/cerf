#include "../../socs/omap3530/omap3530_board_clock_setup.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "omap_3530_evm_id.h"

#include <cstdint>

namespace {

constexpr uint64_t kOscSysClkHz = 26000000ull;

constexpr uint32_t kMpuDpllFreqSel = 7u;
constexpr uint32_t kMpuDpllLock    = 7u;
constexpr uint32_t kMpuClkSrc      = 1u;
constexpr uint32_t kMpuDpllMult    = 300u;
constexpr uint32_t kMpuDpllDiv     = 12u;
constexpr uint32_t kMpuDpllM2      = 1u;

constexpr uint32_t kPeriphDpllFreqSel = 7u;
constexpr uint32_t kPeriphDpllLock    = 7u;
constexpr uint32_t kPeriphDpllMult    = 216u;
constexpr uint32_t kPeriphDpllDiv     = 12u;

class OmapEvm3530ClockSetup : public Omap3530BoardClockSetup {
public:
    using Omap3530BoardClockSetup::Omap3530BoardClockSetup;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetBoardId() == BoardId::Omap3530Evm;
    }

    uint64_t OscSysClkHz() const override { return kOscSysClkHz; }

    /* TI SWCU056C Figure 2 (printed p. 9): TPS65950 HFCLKOUT drives OMAP3530
       sys_xtalin, sys_xtalout unconnected; §3.1.1 (printed p. 8): the TPS65950
       "delivers a square digital waveform to the entire applicative system". */
    bool SysXtalinIsSquareClock() const override { return true; }

    Omap3530MpuDpllSetting BootMpuDpll() const override {
        return { (kMpuDpllFreqSel << 4) | kMpuDpllLock,
                 (kMpuClkSrc << 19) | (kMpuDpllMult << 8) | kMpuDpllDiv,
                 kMpuDpllM2 };
    }

    Omap3530PeriphDpllSetting BootPeriphDpll() const override {
        return { (kPeriphDpllFreqSel << 20) | (kPeriphDpllLock << 16),
                 (kPeriphDpllMult << 8) | kPeriphDpllDiv };
    }

    bool BootEnablesGpt1Clocks() const override { return true; }
};

}

REGISTER_SERVICE_AS(OmapEvm3530ClockSetup, Omap3530BoardClockSetup);
