#include "../freescale_timer_clocks.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "imx51_ccm.h"
#include "imx51_id.h"

#include <cstdint>

namespace {

/* MCIMX51RM Table 7-35 CCGR2: CG1 epit1_ipg_clk, CG2 epit1_highfreq, CG3
   epit2_ipg_clk, CG4 epit2_highfreq, CG9 gpt_ipg_clk, CG10 gpt_highfreq. */
constexpr uint32_t kCcgr2 = 2u;

class Imx51TimerClocks : public FreescaleTimerClocks {
public:
    using FreescaleTimerClocks::FreescaleTimerClocks;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == SocId::Imx51;
    }

    void OnReady() override { ccm_ = &emu_.Get<Imx51Ccm>(); }

    /* MCIMX51RM Table 7-41: epit1_highfreq, epit2_highfreq and gpt_highfreq are
       PERCLK-dependent. */
    uint64_t InputHz(FreescaleTimerUnit unit, FreescaleTimerInput input) const override {
        if (input == FreescaleTimerInput::kLowfreq) {
            emu_.Get<Fatal>().Die("Imx51TimerClocks: timer unit %u selects the ipg_clk_32k "
                                  "input", static_cast<unsigned>(unit));
        }
        if (!InputRunsIn(unit, input, FreescaleLowPowerMode::kRun)) return 0u;
        if (input == FreescaleTimerInput::kHighfreq) return ccm_->PerclkRootHz();
        return ccm_->IpgClkHz();
    }

    bool InputRunsIn(FreescaleTimerUnit unit, FreescaleTimerInput input,
                     FreescaleLowPowerMode mode) const override {
        return ccm_->ClockRunsIn(kCcgr2, GateIndex(unit, input), mode);
    }

    /* MCIMX51RM Table 7-26 CLPCR LPM [1:0]: 00 remain in run mode, 01 wait mode,
       10 STOP mode, 11 LPSR mode. */
    FreescaleLowPowerMode WfiMode() const override {
        switch (ccm_->WfiLowPowerMode()) {
            case 0u: return FreescaleLowPowerMode::kRun;
            case 1u: return FreescaleLowPowerMode::kWait;
            case 2u: return FreescaleLowPowerMode::kStop;
            default: break;
        }
        emu_.Get<Fatal>().Die("Imx51TimerClocks: CLPCR selects LPSR mode");
    }

    void RegisterRateListener(std::function<void()> fn) override {
        ccm_->RegisterRateListener(std::move(fn));
    }

private:
    static uint32_t GateIndex(FreescaleTimerUnit unit, FreescaleTimerInput input) {
        const bool hf = input == FreescaleTimerInput::kHighfreq;
        switch (unit) {
            case FreescaleTimerUnit::kEpit1: return hf ? 2u : 1u;
            case FreescaleTimerUnit::kEpit2: return hf ? 4u : 3u;
            default:                         return hf ? 10u : 9u;
        }
    }

    Imx51Ccm* ccm_ = nullptr;
};

}

REGISTER_SERVICE_AS(Imx51TimerClocks, FreescaleTimerClocks);
