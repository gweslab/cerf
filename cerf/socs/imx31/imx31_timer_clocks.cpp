#include "../freescale_timer_clocks.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "imx31_ccm.h"
#include "imx31_id.h"

#include <cstdint>

namespace {

/* MCIMX31RM Table 3-13: CGR0 CG2 GPT, CG3 EPIT1, CG4 EPIT2. */
constexpr uint32_t kGateGpt   = 2u;
constexpr uint32_t kGateEpit1 = 3u;
constexpr uint32_t kGateEpit2 = 4u;

class Imx31TimerClocks : public FreescaleTimerClocks {
public:
    using FreescaleTimerClocks::FreescaleTimerClocks;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == SocId::Imx31;
    }

    void OnReady() override { ccm_ = &emu_.Get<Imx31Ccm>(); }

    uint64_t InputHz(FreescaleTimerUnit unit, FreescaleTimerInput input) const override {
        if (ccm_->ClockGate0(GateIndex(unit)) == 0u) return 0u;
        if (input == FreescaleTimerInput::kLowfreq)  return ccm_->CkilHz();
        if (input == FreescaleTimerInput::kHighfreq) return ccm_->PerClkHz();
        return ccm_->IpgClkHz();
    }

    /* MCIMX31RM Table 3-30 transition 8 stops the PLLs; 33.6.1.1 and 34.4.1.1 keep
       ipg_clk_32k on in low-power mode; Table 3-12 CG 11. */
    bool InputRunsIn(FreescaleTimerUnit unit, FreescaleTimerInput input,
                     FreescaleLowPowerMode mode) const override {
        const uint32_t cg = ccm_->ClockGate0(GateIndex(unit));
        if (mode == FreescaleLowPowerMode::kStateRetention &&
            input == FreescaleTimerInput::kLowfreq) {
            return cg == 3u;
        }
        return Imx31Ccm::ClockGateRunsIn(cg, mode);
    }

    FreescaleLowPowerMode WfiMode() const override { return ccm_->WfiMode(); }

    void RegisterRateListener(std::function<void()> fn) override {
        ccm_->RegisterRateListener(std::move(fn));
    }

private:
    static uint32_t GateIndex(FreescaleTimerUnit unit) {
        switch (unit) {
            case FreescaleTimerUnit::kEpit1: return kGateEpit1;
            case FreescaleTimerUnit::kEpit2: return kGateEpit2;
            default:                         return kGateGpt;
        }
    }

    Imx31Ccm* ccm_ = nullptr;
};

}

REGISTER_SERVICE_AS(Imx31TimerClocks, FreescaleTimerClocks);
