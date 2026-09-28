#pragma once

#include "../../peripherals/peripheral_base.h"
#include "../../host/guest_deep_sleep.h"
#include "../guest_cpu_reset.h"
#include "../pxa2xx/pxa2xx_gpio.h"

#include <atomic>
#include <cstdint>

class Pxa255PowerManager : public Peripheral,
                           public DeepSleepWaker,
                           public ResetCauseLatch,
                           public Pxa2xxGpioWakeSink {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x40F00000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord (uint32_t addr) override;
    uint8_t  ReadByte (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

    void LatchSleepWakeCause() override;
    void ClearSleepWakeCause() override;

    void LatchWarmReset() override;
    void LatchColdReset() override;
    void LatchWatchdogReset() override;

    void OnInputEdges(uint32_t rose, uint32_t fell) override;

    bool RtcAlarmWakeEnabled() const;
    void LatchRtcWakeEdge();

private:
    void OnResetLine(ResetLineKind kind);
    void OnSleepEntry();

    uint32_t pmcr_  = 0;
    uint32_t pssr_  = 0x20u;
    uint32_t pspr_  = 0;
    uint32_t pcfr_  = 0;
    uint32_t pgsr0_ = 0;
    uint32_t pgsr1_ = 0;
    uint32_t pgsr2_ = 0;

    std::atomic<uint32_t> pwer_{0x3u};
    std::atomic<uint32_t> prer_{0x3u};
    std::atomic<uint32_t> pfer_{0x3u};
    std::atomic<uint32_t> pedr_{0u};
    std::atomic<uint32_t> rcsr_{0x1u};
    std::atomic<uint32_t> wake_edges_{0u};
    std::atomic<bool>     asleep_{false};
};
