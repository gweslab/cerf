#pragma once

#include "../guest_cpu_reset.h"
#include "../irq_controller.h"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <thread>

struct BlockContext;
struct DecodedInsn;
class StateReader;
class StateWriter;

class Iop13xxCp6 : public IrqController, public ResetCauseLatch {
public:
    using IrqController::IrqController;
    ~Iop13xxCp6() override;

    bool ShouldRegister() override;
    void OnReady() override;
    void OnShutdown() override;

    void AssertIrq(int source_bit) override;
    void AssertSubIrq(int main_source_bit, int sub_source_bit) override;
    void DeAssertIrq(int source_bit) override;
    void SetSharedIrqLevel(int source_bit, uint32_t contributor_bit, bool asserted) override;
    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);
    void PostRestoreState();

    uint8_t* EmitRegisterTransfer(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

    static uint32_t __fastcall ReadHelper(Iop13xxCp6* self, uint32_t key);
    static void __fastcall WriteHelper(Iop13xxCp6* self, uint32_t key, uint32_t value);

    void LatchWarmReset() override;
    void LatchColdReset() override;
    void LatchWatchdogReset() override;

private:
    struct Timer {
        uint32_t control = 0;
        uint32_t counter = 0;
        uint32_t reload = 0;
        uint32_t base_cycles = 0;
    };

    static constexpr uint32_t kTimerEnable = 0x02u;
    static constexpr uint32_t kTimerReload = 0x04u;
    static constexpr uint32_t kTimer0Irq = 8u;
    static constexpr uint32_t kTimer1Irq = 9u;
    static constexpr uint32_t kTimerTicksPerMicrosecond = 25u;
    static constexpr uint32_t kWatchdogIrq = 6u;
    static constexpr uint64_t kWatchdogTimeoutTicks = 0xFFFFFFFFull;
    static constexpr uint32_t kWatchdogEnableArm = 0x1E1E1E1Eu;
    static constexpr uint32_t kWatchdogEnable = 0xE1E1E1E1u;
    static constexpr uint32_t kWatchdogDisableArm = 0x1F1F1F1Fu;
    static constexpr uint32_t kWatchdogDisable = 0xF1F1F1F1u;
    static constexpr uint32_t kWatchdogImmediate = 0x00001000u;
    static constexpr uint32_t kWatchdogStatusWriteEnable = 1u << 31;
    static constexpr uint32_t kWatchdogStatusInternalBusReset = 1u << 0;
    static constexpr uint32_t kResetCauseCoreTargeted = 1u << 4;
    static constexpr uint32_t kResetCauseWatchdog = 1u << 5;

    uint32_t TimerTicks() const;
    void TimerLoop();
    void AdvanceTimersLocked(uint32_t cycles_now);
    void AdvanceTimerLocked(Timer& timer, uint32_t cycles_now, uint32_t status_bit);
    void AdvanceWatchdogLocked(uint32_t ticks_now);
    void WriteWatchdogControlLocked(uint32_t value, uint32_t ticks_now);
    void WriteWatchdogStatusLocked(uint32_t value);
    uint32_t ReadRegisterLocked(uint32_t key, uint32_t cycles_now);
    void WriteRegisterLocked(uint32_t key, uint32_t value, uint32_t cycles_now);
    uint32_t InterruptVectorLocked() const;
    bool HasPendingIrqLocked() const;
    void NotifyLocked();
    bool HasPendingFiqLocked() const;
    void ResetStateLocked(uint32_t ticks_now);

    mutable std::mutex state_mutex_;
    uint32_t intctl_[4]{};
    uint32_t intstr_[4]{};
    uint32_t pending_[4]{};
    uint32_t shared_irq_levels_[128]{};
    uint32_t intbase_ = 0;
    uint32_t intsize_ = 0;
    uint32_t tisr_ = 0;
    uint32_t rcsr_ = 0;
    uint32_t wdtsr_ = 0;
    uint64_t watchdog_elapsed_ticks_ = 0;
    uint32_t watchdog_last_ticks_ = 0;
    bool watchdog_enabled_ = false;
    bool watchdog_enable_armed_ = false;
    bool watchdog_disable_armed_ = false;
    uint64_t timer_epoch_us_ = 0;
    Timer timer_[2]{};

    std::thread timer_thread_;
    std::atomic<bool> stop_thread_{false};
    std::atomic<bool> watchdog_reset_requested_{false};
};
