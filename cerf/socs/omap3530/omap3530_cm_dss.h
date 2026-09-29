#pragma once

#include "omap3530_cm_clock_control.h"
#include "omap3530_prcm_stub_block.h"

#include <cstdint>
#include <functional>
#include <vector>

class Omap3530CmDss : public Omap3530PrcmStubBlock {
public:
    using Omap3530PrcmStubBlock::Omap3530PrcmStubBlock;

    uint32_t MmioBase() const override { return 0x48004E00u; }
    uint32_t MmioSize() const override { return 0x00000100u; }

    void OnReady() override;

    void WriteWord(uint32_t addr, uint32_t value) override;
    void WriteHalf(uint32_t addr, uint16_t value) override;


    GuestCycleClock::Rate Dss1AlwonFclk() const;
    bool Dss1FclkEnabled() const;

    void RegisterDss1Listener(std::function<void()> fn);

protected:
    const char* Label() const override { return "CM_DSS"; }
    const char* RegisterName(uint32_t off) const override;

private:
    void ApplyResetsLocked();

    Omap3530CmClockControl*            clock_control_ = nullptr;
    std::vector<std::function<void()>> dss1_listeners_;
};
