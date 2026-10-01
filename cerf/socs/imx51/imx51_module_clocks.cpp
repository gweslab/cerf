#include "../freescale_module_clocks.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "imx51_ccm.h"
#include "imx51_id.h"

#include <cstdint>
#include <functional>
#include <utility>
#include <vector>

namespace {

struct ClockRef { uint32_t ccgr; uint32_t cg; };

struct ModuleClocks {
    FreescaleModule module;
    ClockRef        clocks[3];
    uint32_t        clock_count;
};

/* MCIMX51RM Table 7-33 (CCGR0) to Table 7-39 (CCGR6). */
constexpr ModuleClocks kModules[] = {
    {FreescaleModule::kRom,         {{0, 11}},                  1},
    {FreescaleModule::kIim,         {{0, 15}},                  1},
    {FreescaleModule::kUart1,       {{1, 3}, {1, 4}},           2},
    {FreescaleModule::kUart2,       {{1, 5}, {1, 6}},           2},
    {FreescaleModule::kUart3,       {{1, 7}, {1, 8}},           2},
    {FreescaleModule::kUart1Ipg,    {{1, 3}},                   1},
    {FreescaleModule::kUart2Ipg,    {{1, 5}},                   1},
    {FreescaleModule::kUart3Ipg,    {{1, 7}},                   1},
    {FreescaleModule::kI2c1,        {{1, 9}},                   1},
    {FreescaleModule::kI2c2,        {{1, 10}},                  1},
    {FreescaleModule::kUsbPhy,      {{2, 0}},                   1},
    {FreescaleModule::kUsboh3Clk60, {{2, 14}},                  1},
    {FreescaleModule::kEsdhc2,      {{3, 2}, {3, 3}},           2},
    {FreescaleModule::kSsi1,        {{3, 8}, {3, 9}},           2},
    {FreescaleModule::kSsi2,        {{3, 10}, {3, 11}},         2},
    {FreescaleModule::kSsi3,        {{3, 12}, {3, 13}},         2},
    {FreescaleModule::kEcspi1,      {{4, 9}, {4, 10}},          2},
    {FreescaleModule::kSdma,        {{4, 15}},                  1},
    {FreescaleModule::kGpu3dCore,   {{5, 1}},                   1},
    {FreescaleModule::kGpu3dMemory, {{5, 2}},                   1},
    {FreescaleModule::kVpu,         {{5, 3}},                   1},
    {FreescaleModule::kNfc,         {{5, 10}},                  1},
    {FreescaleModule::kGpu2d,       {{6, 7}},                   1},
};

struct SystemClock { const char* name; ClockRef clock; };

/* MCIMX51RM Table 7-33 arm_bus, arm_axi, tzic, ahbmux1/2, aips_tz1/2, ahb_max; Table 7-38 spba,
   emi_fast, emi_slow, emi_int1; §57.4.7 "The ACLK input must receive a clock signal at all times". */
constexpr SystemClock kSystemClocks[] = {
    {"arm_bus", {0, 0}},   {"arm_axi", {0, 1}},   {"tzic", {0, 3}},      {"ahbmux1", {0, 8}},
    {"ahbmux2", {0, 9}},   {"aips_tz1", {0, 12}}, {"aips_tz2", {0, 13}}, {"ahb_max", {0, 14}},
    {"spba", {5, 0}},      {"emi_fast", {5, 7}},  {"emi_slow", {5, 8}},  {"emi_int1", {5, 9}},
};

class Imx51ModuleClocks : public FreescaleModuleClocks {
public:
    using FreescaleModuleClocks::FreescaleModuleClocks;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == SocId::Imx51;
    }

    void OnReady() override {
        ccm_ = &emu_.Get<Imx51Ccm>();
        ccm_->RegisterGateListener([this] { OnGatesChanged(); });
        OnGatesChanged();
    }

    bool ModuleRunsIn(FreescaleModule module, FreescaleLowPowerMode mode) const override {
        const ModuleClocks& m = Row(module);
        for (uint32_t c = 0u; c < m.clock_count; ++c) {
            if (!ccm_->ClockRunsIn(m.clocks[c].ccgr, m.clocks[c].cg, mode)) return false;
        }
        return true;
    }

    void RegisterGateListener(std::function<void()> fn) override {
        listeners_.push_back(std::move(fn));
    }

private:
    const ModuleClocks& Row(FreescaleModule module) const {
        for (const ModuleClocks& m : kModules) {
            if (m.module == module) return m;
        }
        emu_.Get<Fatal>().Die("Imx51ModuleClocks: module %u has no i.MX51 clock mapping",
                              static_cast<unsigned>(module));
    }

    void OnGatesChanged() {
        for (const SystemClock& s : kSystemClocks) {
            if (!ccm_->ClockRunsIn(s.clock.ccgr, s.clock.cg, FreescaleLowPowerMode::kRun)) {
                emu_.Get<Fatal>().Die("Imx51ModuleClocks: CCGR%u CG%u (%s) is off in run mode; "
                                      "stopping that clock is not modeled", s.clock.ccgr,
                                      s.clock.cg, s.name);
            }
        }
        for (auto& fn : listeners_) fn();
    }

    Imx51Ccm*                          ccm_ = nullptr;
    std::vector<std::function<void()>> listeners_;
};

}

REGISTER_SERVICE_AS(Imx51ModuleClocks, FreescaleModuleClocks);
