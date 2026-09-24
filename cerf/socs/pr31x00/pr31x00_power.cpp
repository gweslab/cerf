#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "pr31500_id.h"
#include "pr31700_id.h"
#include "../../core/cerf_emulator.h"
#include "../../host/guest_deep_sleep.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "pr31x00_intc.h"
#include "pr31x00_power_inputs.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>

namespace {

/* PR31x00 Power module. The single Power Control Register sits at offset $1C4 of
   the Internal Function Registers (PA 0x10C00000, TMPR3911/3912 Table 4.2.1);
   field layout and reset values per §12.3.1. */
constexpr uint32_t kBase = 0x10C001C4u;
constexpr uint32_t kSize = 0x4u;

constexpr uint32_t kOnButn    = 1u << 31;   /* R: ONBUTN signal status */
constexpr uint32_t kPwrInt    = 1u << 30;   /* R: PWRINT signal status */
constexpr uint32_t kPwrOk     = 1u << 29;   /* R: PWROK signal status */
constexpr uint32_t kStpTimerVal = 0xF000u;  /* STPTIMERVAL[3:0]<15:12> (§12.3.1) */
constexpr uint32_t kStpTimerValShift = 12u;
constexpr uint32_t kEnStpTimer = 1u << 11;  /* ENSTPTIMER (§12.3.1) */
constexpr uint32_t kForceShutDwn = 1u << 9;
constexpr uint32_t kColdStart = 1u << 2;    /* set by RESET: a power-on reset occurred */
constexpr uint32_t kPwrCs     = 1u << 1;
constexpr uint32_t kVccOn     = 1u << 0;

constexpr uint32_t kWritable = 0x1E00FFBFu;   /* VIDRF..DIVMOD, STPTIMERVAL..SELC2MS, BPDBVCC3..VCCON */
constexpr uint32_t kReadOnly = kOnButn | kPwrInt | kPwrOk;

/* STPTIMERINT = Interrupt Status 5 (set index 4) bit 28 (§8.3.5; NetBSD
   tx39icureg.h). The Stop Timer counts on an 8 ms clock and raises STPTIMERINT
   when the 4-bit up-counter reaches STPTIMERVAL, i.e. after STPTIMERVAL × 8 ms;
   clearing ENSTPTIMER resets the counter (§12.2.8). */
constexpr uint32_t kStpIntStatusSet = 4u;
constexpr uint32_t kStpTimerInt     = 1u << 28;
constexpr auto     kStpTick         = std::chrono::milliseconds(8);

constexpr uint32_t kCauseNone = 0;
constexpr uint32_t kCauseWarm = 1;
constexpr uint32_t kCauseCold = 2;

class Pr31x00Power : public Peripheral, public ResetCauseLatch, public DeepSleepClockStop {
public:
    using Peripheral::Peripheral;

    ~Pr31x00Power() override { StopStpWorker(); }
    void OnShutdown() override { StopStpWorker(); }

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        if (!bd) return false;
        const std::string_view soc = bd->GetSocId();
        return soc == SocId::Pr31500 || soc == SocId::Pr31700;
    }
    void OnReady() override {
        intc_ = &emu_.Get<Pr31x00Intc>();
        power_inputs_ = emu_.TryGet<Pr31x00PowerInputs>();
        emu_.Get<PeripheralDispatcher>().Register(this);
        auto& reset = emu_.Get<GuestCpuReset>();
        reset.SetCauseLatch(this);
        reset.RegisterResetListener([this](ResetLineKind) { ApplyResetCause(); });
        emu_.Get<GuestDeepSleep>().RegisterClockStopWaker(this);
        stp_worker_ = std::thread([this] { StpWorkerLoop(); });
    }

    /* PWRCS and VCCON are "set whenever the ONBUTN signal is asserted or an enabled
       interrupt occurs while the PWROK signal is high", and "FORCESHUTDWN ... is set
       whenever the VCCON bit and the PWRCS bit are set by either the ONBUTN signal
       assertion or an enabled interrupt occurrence" (§12.3.1, p.12-13/12-14). */
    void OnPowerUp() override {
        ctl_.fetch_or(kPwrCs | kVccOn | kForceShutDwn, std::memory_order_acq_rel);
    }

    /* "COLDSTART: This bit is set by RESET" (§12.3.1, p.12-14). */
    void LatchColdReset() override { pending_cause_.store(kCauseCold, std::memory_order_release); }
    void LatchWarmReset() override { pending_cause_.store(kCauseWarm, std::memory_order_release); }

    /* No PR31x00 watchdog is modelled, so nothing raises this cause. */
    void LatchWatchdogReset() override {
        HaltUnsupportedAccess("PR31x00 Power watchdog reset cause", kBase, Ctl());
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override {
        if (addr != kBase) {
            HaltUnsupportedAccess("PR31x00 Power ReadWord", addr, 0);
        }
        uint32_t sig = signals_;
        if (power_inputs_ && power_inputs_->PwrIntAsserted()) {
            sig |= kPwrInt;
        }
        return Ctl() | sig;
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        if (addr != kBase) {
            HaltUnsupportedAccess("PR31x00 Power WriteWord", addr, value);
        }
        const uint32_t prev = Ctl();
        const uint32_t next = value & kWritable;
        ctl_.store(next, std::memory_order_release);

        /* "When powering down the system, [VCCON] must be cleared simultaneously
           with the PWRCS bit" (§12.3.1) - the guest turning the machine off. */
        const bool was_on = (prev & (kVccOn | kPwrCs)) != 0u;
        const bool now_off = (next & (kVccOn | kPwrCs)) == 0u;
        if (was_on && now_off) {
            emu_.Get<GuestDeepSleep>().Enter();
        }

        /* ENSTPTIMER edge: a rising edge starts the Stop Timer counter, a falling
           edge resets it (§12.2.8). */
        const bool was_stp = (prev & kEnStpTimer) != 0u;
        const bool now_stp = (next & kEnStpTimer) != 0u;
        if (now_stp && !was_stp) {
            ArmStopTimer((next & kStpTimerVal) >> kStpTimerValShift);
        } else if (was_stp && !now_stp) {
            DisarmStopTimer();
        }
    }

    uint8_t  ReadByte (uint32_t addr) override { HaltUnsupportedAccess("PR31x00 Power ReadByte", addr, 0); }
    uint16_t ReadHalf (uint32_t addr) override { HaltUnsupportedAccess("PR31x00 Power ReadHalf", addr, 0); }
    void WriteByte(uint32_t addr, uint8_t  v) override { HaltUnsupportedAccess("PR31x00 Power WriteByte", addr, v); }
    void WriteHalf(uint32_t addr, uint16_t v) override { HaltUnsupportedAccess("PR31x00 Power WriteHalf", addr, v); }

    void SaveState(StateWriter& w) override {
        w.Write("ctl", Ctl()); w.Write("signals", signals_);
        w.Write("pending_cause", pending_cause_.load(std::memory_order_acquire));
    }
    void RestoreState(StateReader& r) override {
        uint32_t ctl = 0;
        r.Read("ctl", ctl);
        ctl_.store(ctl, std::memory_order_release);
        r.Read("signals", signals_);
        uint32_t cause = kCauseNone;
        r.Read("pending_cause", cause);
        pending_cause_.store(cause, std::memory_order_release);
    }

    void PostRestore() override {
        if (Ctl() & kEnStpTimer) {
            ArmStopTimer((Ctl() & kStpTimerVal) >> kStpTimerValShift);
        } else {
            DisarmStopTimer();
        }
    }

private:
    using Clock = std::chrono::steady_clock;

    uint32_t Ctl() const { return ctl_.load(std::memory_order_acquire); }

    void ApplyResetCause() {
        switch (pending_cause_.exchange(kCauseNone, std::memory_order_acq_rel)) {
            case kCauseCold: ctl_.fetch_or(kColdStart, std::memory_order_acq_rel);   return;
            case kCauseWarm: ctl_.fetch_and(~kColdStart, std::memory_order_acq_rel); return;
            default:
                HaltUnsupportedAccess("PR31x00 Power reset delivered with no cause latched",
                                      kBase, Ctl());
        }
    }

    void ArmStopTimer(uint32_t stptimerval) {
        {
            std::lock_guard<std::mutex> lk(stp_mtx_);
            stp_deadline_ = Clock::now() + kStpTick * stptimerval;
            stp_armed_    = true;
        }
        NotifyStpWorker();
    }

    void DisarmStopTimer() {
        {
            std::lock_guard<std::mutex> lk(stp_mtx_);
            stp_armed_ = false;
        }
        NotifyStpWorker();
    }

    void NotifyStpWorker() {
        { std::lock_guard<std::mutex> g(stp_cv_mtx_); stp_rearm_ = true; }
        stp_cv_.notify_all();
    }

    void StopStpWorker() {
        if (!stp_worker_.joinable()) return;
        stp_stop_.store(true);
        NotifyStpWorker();
        stp_worker_.join();
    }

    void StpWorkerLoop() {
        auto& freeze = emu_.Get<EmulationFreeze>();
        while (!stp_stop_.load()) {
            Clock::time_point deadline = Clock::time_point::max();
            {
                auto frozen = freeze.WorkerSection();
                std::lock_guard<std::mutex> lk(stp_mtx_);
                if (stp_armed_) {
                    if (Clock::now() >= stp_deadline_) {
                        stp_armed_ = false;
                        intc_->SetPending(kStpIntStatusSet, kStpTimerInt);
                    } else {
                        deadline = stp_deadline_;
                    }
                }
            }
            std::unique_lock<std::mutex> lk(stp_cv_mtx_);
            const auto woke = [this] { return stp_stop_.load() || stp_rearm_; };
            if (deadline == Clock::time_point::max()) {
                stp_cv_.wait(lk, woke);
            } else {
                stp_cv_.wait_until(lk, deadline, woke);
            }
            stp_rearm_ = false;
        }
    }

    std::atomic<uint32_t> ctl_{kColdStart};

    uint32_t signals_ = kPwrOk;

    std::atomic<uint32_t> pending_cause_{kCauseNone};

    Pr31x00Intc* intc_ = nullptr;
    Pr31x00PowerInputs* power_inputs_ = nullptr;

    std::mutex        stp_mtx_;
    Clock::time_point stp_deadline_{};
    bool              stp_armed_ = false;

    std::mutex              stp_cv_mtx_;
    std::condition_variable stp_cv_;
    bool                    stp_rearm_ = false;
    std::thread             stp_worker_;
    std::atomic<bool>       stp_stop_{false};

    static_assert((kWritable & kReadOnly) == 0u, "writable and read-only fields overlap");
};

}  /* namespace */

REGISTER_SERVICE(Pr31x00Power);
