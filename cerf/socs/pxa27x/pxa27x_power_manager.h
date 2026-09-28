#pragma once

#include "../../peripherals/peripheral_base.h"
#include "../../host/guest_deep_sleep.h"
#include "../guest_cpu_reset.h"
#include "../pxa2xx/pxa2xx_gpio.h"

#include <atomic>
#include <cstdint>

class Pxa27xPowerManager : public Peripheral,
                           public DeepSleepWaker,
                           public ResetCauseLatch,
                           public Pxa2xxGpioWakeSink {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x40F00000u; }
    uint32_t MmioSize() const override { return 0x00000100u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

    void LatchSleepWakeCause() override;
    void ClearSleepWakeCause() override;

    void LatchWarmReset() override;
    void LatchColdReset() override;
    void LatchWatchdogReset() override;

    void OnInputEdges(uint32_t rose, uint32_t fell) override;

    bool RtcWakeEnabled() const;
    void LatchRtcWakeEdge();
    bool FrequencyVoltageChange() const;

private:
    void OnResetLine(ResetLineKind kind);
    void OnSleepExitRelease();
    void OnSleepEntry();
    void ResetForSleepExit();
    void ResetAll(bool keep_gprod);
    void WritePssr(uint32_t value);

    uint32_t pmcr_ = 0, pspr_ = 0, pcfr_ = 0, pstr_ = 0, pvcr_ = 0, pucr_ = 0, pksr_ = 0;
    uint32_t pssr_ = 0x20u;
    uint32_t pslr_ = 0xCC000000u;
    uint32_t pkwr_ = 0;
    uint32_t pgsr_[4]  = {};
    uint32_t pcmd_[32] = {};

    std::atomic<uint32_t> pwer_{0x3u};
    std::atomic<uint32_t> prer_{0x3u};
    std::atomic<uint32_t> pfer_{0x3u};
    std::atomic<uint32_t> pedr_{0u};
    std::atomic<uint32_t> rcsr_{0u};
    std::atomic<uint32_t> wake_edges_{0u};
    std::atomic<bool>     asleep_{false};
};
