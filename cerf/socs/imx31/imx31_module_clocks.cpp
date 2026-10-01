#include "../freescale_module_clocks.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "imx31_ccm.h"
#include "imx31_id.h"

#include <cstdint>
#include <functional>
#include <utility>
#include <vector>

namespace {

struct ModuleGate {
    FreescaleModule module;
    uint32_t        cgr;
    uint32_t        cg;
    bool            run_gateable;
};

/* MCIMX31RM Table 3-13 (CGR0), Table 3-14 (CGR1), Table 3-15 (CGR2); Table 3-12 note: "RTIC, SDMA,
   IPU, and EMI clock gating is not possible during run mode." */
constexpr ModuleGate kModules[] = {
    {FreescaleModule::kSdhc1,    0, 0,  true},
    {FreescaleModule::kIim,      0, 5,  true},
    {FreescaleModule::kAta,      0, 6,  true},
    {FreescaleModule::kSdma,     0, 7,  false},
    {FreescaleModule::kCspi3,    0, 8,  true},
    {FreescaleModule::kSsi1,     0, 12, true},
    {FreescaleModule::kI2c1,     0, 13, true},
    {FreescaleModule::kI2c2,     0, 14, true},
    {FreescaleModule::kI2c3,     0, 15, true},
    {FreescaleModule::kUsbotg,   1, 9,  true},
    {FreescaleModule::kUart5,    1, 14, true},
    {FreescaleModule::kUart5Ipg, 1, 14, true},
    {FreescaleModule::kOwire,    1, 15, true},
    {FreescaleModule::kSsi2,     2, 0,  true},
    {FreescaleModule::kCspi2,    2, 2,  true},
};

class Imx31ModuleClocks : public FreescaleModuleClocks {
public:
    using FreescaleModuleClocks::FreescaleModuleClocks;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == SocId::Imx31;
    }

    void OnReady() override {
        ccm_ = &emu_.Get<Imx31Ccm>();
        ccm_->RegisterGateListener([this] { for (auto& fn : listeners_) fn(); });
    }

    bool ModuleRunsIn(FreescaleModule module, FreescaleLowPowerMode mode) const override {
        const ModuleGate& m = Row(module);
        if (mode == FreescaleLowPowerMode::kRun && !m.run_gateable) return true;
        return Imx31Ccm::ClockGateRunsIn(ccm_->ClockGate(m.cgr, m.cg), mode);
    }

    void RegisterGateListener(std::function<void()> fn) override {
        listeners_.push_back(std::move(fn));
    }

private:
    const ModuleGate& Row(FreescaleModule module) const {
        for (const ModuleGate& m : kModules) {
            if (m.module == module) return m;
        }
        emu_.Get<Fatal>().Die("Imx31ModuleClocks: module %u has no i.MX31 clock mapping",
                              static_cast<unsigned>(module));
    }

    Imx31Ccm*                          ccm_ = nullptr;
    std::vector<std::function<void()>> listeners_;
};

}

REGISTER_SERVICE_AS(Imx31ModuleClocks, FreescaleModuleClocks);
