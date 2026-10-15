#include "guest_deep_sleep.h"
#include "ui_language.h"

#include "../boot/guest_cold_boot.h"
#include "../core/cerf_emulator.h"
#include "../core/fatal.h"
#include "../core/log.h"
#include "../core/steady_time.h"
#include "../execution/engine_bridge.h"
#include "../state/shutdown_action.h"
#include "../state/shutdown_dialog.h"
#include "guest_power_notifier.h"
#include "host_window.h"
#include "notification_stack.h"

#include <chrono>

REGISTER_SERVICE(GuestDeepSleep);

namespace {
constexpr int kResumeGraceMs = 100;
}

void GuestDeepSleep::RequireNoWakeShape(const char* shape) const {
    if (waker_ == nullptr && clock_stop_ == nullptr && !power_on_wake_) return;
    emu_.Get<Fatal>().Die("GuestDeepSleep: a %s wake registered beside another wake shape", shape);
}

void GuestDeepSleep::RegisterWaker(DeepSleepWaker* waker) {
    RequireNoWakeShape("reset");
    waker_ = waker;
}

void GuestDeepSleep::RegisterClockStopWaker(DeepSleepClockStop* waker) {
    RequireNoWakeShape("clock-stop");
    clock_stop_ = waker;
}

void GuestDeepSleep::RegisterPowerOnWake() {
    RequireNoWakeShape("power-on");
    power_on_wake_ = true;
}

void GuestDeepSleep::RegisterPowerUpListener(std::function<void()> fn) {
    power_up_listeners_.push_back(std::move(fn));
}

void GuestDeepSleep::RegisterUserWakeInput(std::function<void()> fn) {
    user_wake_inputs_.push_back(std::move(fn));
}

void GuestDeepSleep::RegisterSleepEntryListener(std::function<void()> fn) {
    sleep_entry_listeners_.push_back(std::move(fn));
}

void GuestDeepSleep::RegisterParkClock(std::function<void()> fn) {
    park_clocks_.push_back(std::move(fn));
}

void GuestDeepSleep::RegisterParkWakeSource(std::function<bool()> fn) {
    park_wake_sources_.push_back(std::move(fn));
}

void GuestDeepSleep::RegisterParkWakeDue(std::function<int64_t()> fn) {
    park_wake_dues_.push_back(std::move(fn));
}

void GuestDeepSleep::PollPark() {
    int64_t due  = kNoParkWake;
    int64_t span = 0;
    {
        std::lock_guard<std::mutex> lk(span_mtx_);
        if (sleep_entry_ns_ != 0) {
            due  = park_due_ns_;
            span = slept_ns_ + (HostSteadyNanos() - sleep_entry_ns_);
        }
    }
    for (auto& fn : park_clocks_) fn();
    for (auto& fn : park_wake_sources_) {
        if (!fn()) continue;
        LOG(SocReset, "[DEEPSLEEP] PollPark: wake-up event from a park wake source\n");
        TearDownPromptForHardwareWake();
        DeliverWake(ResumeSource::Hardware);
        return;
    }
    if (due != kNoParkWake && span >= due) {
        emu_.Get<Fatal>().Die("GuestDeepSleep: the park reached the timer wake due at %lld slept ns "
                              "and no park wake source fired",
                              static_cast<long long>(due));
    }
}

void GuestDeepSleep::FinishPark() {
    for (auto& fn : park_clocks_) fn();
}

int64_t GuestDeepSleep::SleptNs() const {
    std::lock_guard<std::mutex> lk(span_mtx_);
    if (sleep_entry_ns_ == 0) return slept_ns_;
    const int64_t span = slept_ns_ + (HostSteadyNanos() - sleep_entry_ns_);
    return span < park_due_ns_ ? span : park_due_ns_;
}

int64_t GuestDeepSleep::ParkWaitNs() const {
    constexpr int64_t kPollNs = 20000000;
    std::lock_guard<std::mutex> lk(span_mtx_);
    if (sleep_entry_ns_ == 0 || park_due_ns_ == kNoParkWake) return kPollNs;
    const int64_t left = park_due_ns_ - (slept_ns_ + (HostSteadyNanos() - sleep_entry_ns_));
    if (left <= 0) return 0;
    return left < kPollNs ? left : kPollNs;
}

void GuestDeepSleep::ClearWakeCause() {
    if (waker_) waker_->ClearSleepWakeCause();
}

void GuestDeepSleep::RegisterResumeVectorProvider(SleepResumeVectorProvider* p) {
    resume_vector_provider_ = p;
}

void GuestDeepSleep::Enter() {
    if (emu_.Get<EngineBridge>().Guest().ResetPending()) {
        LOG(SocReset, "[DEEPSLEEP] Enter: reset pending, skip (wake/reboot wins)\n");
        return;
    }
    if (active_.exchange(true)) {
        LOG(SocReset, "[DEEPSLEEP] Enter: already active, skip\n");
        return;   /* one prompt per sleep */
    }
    LOG(SocReset, "[DEEPSLEEP] Enter: sleep begin\n");
    wake_claimed_.store(false, std::memory_order_release);
    hw_resumed_.store(false, std::memory_order_release);
    emu_.Get<GuestPowerNotifier>().NotifyPowerDown();
    emu_.Get<EngineBridge>().Guest().EnterDeepSleep();
    for (auto& fn : sleep_entry_listeners_) fn();
    int64_t due = kNoParkWake;
    for (auto& fn : park_wake_dues_) {
        const int64_t d = fn();
        if (d < due) due = d;
    }
    int64_t due_in = 0;
    {
        std::lock_guard<std::mutex> lk(span_mtx_);
        sleep_entry_ns_ = HostSteadyNanos();
        park_due_ns_    = due;
        due_in          = due - slept_ns_;
    }
    if (due != kNoParkWake) {
        LOG(SocReset, "[DEEPSLEEP] Enter: park wake due in %lld ns\n",
            static_cast<long long>(due_in));
    }
    emu_.Get<HostWindow>().RunOnUiThread([this] { Recover(); });
}

void GuestDeepSleep::ObserveAsleep(bool asleep) {
    asleep_.store(asleep, std::memory_order_release);
    auto& stack = emu_.Get<NotificationStack>();
    if (asleep)
        stack.Show(NotificationId::GuestSleeping, NotificationKind::Warning,
                   emu_.Get<UiLanguage>().Text("shutdown.guest_is_in_sleep_mode"));
    else
        stack.Close(NotificationId::GuestSleeping);
}

void GuestDeepSleep::TearDownPromptForHardwareWake() {
    if (!active_.load(std::memory_order_acquire)) return;
    {
        std::lock_guard<std::mutex> lk(resume_mtx_);
        hw_resumed_.store(true, std::memory_order_release);
    }
    resume_cv_.notify_all();
    emu_.Get<HostWindow>().RunOnUiThread(
        [this] { emu_.Get<ShutdownDialog>().DismissAsCancel(); });
}

void GuestDeepSleep::ConsumeSleepSpan() {
    std::lock_guard<std::mutex> lk(span_mtx_);
    if (sleep_entry_ns_ == 0) return;
    const int64_t span = slept_ns_ + (HostSteadyNanos() - sleep_entry_ns_);
    slept_ns_       = span < park_due_ns_ ? span : park_due_ns_;
    sleep_entry_ns_ = 0;
    park_due_ns_    = kNoParkWake;
}

void GuestDeepSleep::DeliverWake(ResumeSource src) {
    if (wake_claimed_.exchange(true, std::memory_order_acq_rel)) return;
    ConsumeSleepSpan();
    if (src == ResumeSource::User) {
        for (auto& fn : user_wake_inputs_) fn();
    }
    if (clock_stop_) {
        clock_stop_->OnPowerUp();
        for (auto& fn : power_up_listeners_) fn();
        emu_.Get<GuestPowerNotifier>().NotifyResume(src);
        emu_.Get<EngineBridge>().Guest().ExitDeepSleep();
        return;
    }
    if (power_on_wake_) {
        emu_.Get<GuestPowerNotifier>().NotifyResume(src);
        emu_.Get<GuestColdBoot>().RequestHardReset();
        return;
    }
    waker_->LatchSleepWakeCause();
    if (resume_vector_provider_) resume_vector_provider_->ApplyPendingResume();
    emu_.Get<EngineBridge>().Guest().SetResetPending(true);
    emu_.Get<GuestPowerNotifier>().NotifyResume(src);
}

void GuestDeepSleep::OnFullRestore() {
    ConsumeSleepSpan();
    wake_claimed_.store(false, std::memory_order_release);
    if (emu_.Get<EngineBridge>().Guest().DeepSleep()) DeliverWake(ResumeSource::User);
}

void GuestDeepSleep::Recover() {
    {
        std::unique_lock<std::mutex> lk(resume_mtx_);
        resume_cv_.wait_for(lk, std::chrono::milliseconds(kResumeGraceMs),
                            [this] { return hw_resumed_.load(std::memory_order_acquire); });
    }
    if (hw_resumed_.exchange(false)) {
        active_.store(false);
        return;
    }
    const ShutdownChoice c =
        emu_.Get<ShutdownDialog>().Show(ShutdownTrigger::DeepSleep);
    LOG(SocReset, "[DEEPSLEEP] Recover: dialog choice=%d (0=Cancel/wake)\n",
        static_cast<int>(c));
    ConsumeSleepSpan();
    const bool hw_resumed = hw_resumed_.exchange(false);
    active_.store(false);
    if (c == ShutdownChoice::Cancel) {
        if (!hw_resumed) DeliverWake(ResumeSource::User);
        return;
    }
    const bool resets = c == ShutdownChoice::SoftReset || c == ShutdownChoice::HardReset;
    if (resets && wake_claimed_.exchange(true, std::memory_order_acq_rel)) {
        LOG(SocReset, "[DEEPSLEEP] Recover: choice=%d dropped, a wake already ended the sleep\n",
            static_cast<int>(c));
        return;
    }
    emu_.Get<ShutdownAction>().Perform(c);
}
