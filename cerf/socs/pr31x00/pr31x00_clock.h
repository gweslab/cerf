#pragma once

#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_base.h"

#include <cstdint>
#include <functional>
#include <vector>

class Pr31x00Clock : public Peripheral {
public:
    using Peripheral::Peripheral;

    void OnReady() override;

    uint32_t MmioBase() const override { return 0x10C001C0u; }
    uint32_t MmioSize() const override { return 0x4u; }

    uint32_t ReadWord(uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    uint8_t  ReadByte(uint32_t addr) override { HaltUnsupportedAccess("PR31x00 CLOCK ReadByte", addr, 0); }
    uint16_t ReadHalf(uint32_t addr) override { HaltUnsupportedAccess("PR31x00 CLOCK ReadHalf", addr, 0); }
    void WriteByte(uint32_t addr, uint8_t  v) override { HaltUnsupportedAccess("PR31x00 CLOCK WriteByte", addr, v); }
    void WriteHalf(uint32_t addr, uint16_t v) override { HaltUnsupportedAccess("PR31x00 CLOCK WriteHalf", addr, v); }

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

    GuestCycleClock::Rate ResetCpuRate() const;
    void     SetPowerClockBits(uint32_t power_ctl);
    GuestCycleClock::Rate VideoClockRate() const;
    void     RegisterVideoClockListener(std::function<void()> fn);

    GuestCycleClock::Rate TimerClockRate() const;
    GuestCycleClock::Rate SibMasterClockRate() const;
    GuestCycleClock::Rate UartClockRate(uint32_t uart_clock_enable) const;
    void                  RegisterModuleClockListener(std::function<void()> fn);

protected:
    uint64_t         PllHz() const;
    virtual uint64_t Clk2xPerCpuClock() const = 0;

private:
    GuestCycleClock::Rate Clk2xRate() const;
    GuestCycleClock::Rate UpperMuxRate() const;
    GuestCycleClock::Rate LowerMuxRate() const;

    void SetCoreRate(uint32_t rf);
    void ApplyCoreRate(uint32_t rf);
    void NotifyVideoClock(GuestCycleClock::Rate before);
    void NotifyModuleClocks();

    uint32_t ctl_   = 0;
    uint32_t power_ = 0;
    std::vector<std::function<void()>> video_listeners_;
    std::vector<std::function<void()>> module_listeners_;
};
