#include "guest_cpu_reset.h"

#include "../boot/guest_cold_boot.h"
#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "../jit/guest_engine.h"

REGISTER_SERVICE(GuestCpuReset);

void GuestCpuReset::SetCauseLatch(ResetCauseLatch* latch) {
    if (latch_ != nullptr) {
        LOG(Caution, "GuestCpuReset: second ResetCauseLatch registered - "
                "one SoC owns the reset-cause register; two implementers "
                "mean a ShouldRegister gate is wrong\n");
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    latch_ = latch;
}

void GuestCpuReset::WarmReset() {
    if (latch_) latch_->LatchWarmReset();
    pending_kind_.store(ResetLineKind::Other, std::memory_order_release);
    emu_.Get<GuestEngine>().SetResetPending(false);
}

/* "When the RTCRST# signal is asserted, the PMU resets all peripheral units including the
   RTC unit" (VR4102 UM 15.1.1(1); Table 15-1 "RTC reset" row: RTC = Reset). The RTC-and-PMU
   exemption is the RSTSW row's (UM 15.1.1(2)). */
void GuestCpuReset::ColdReset() {
    if (latch_) latch_->LatchColdReset();
    pending_kind_.store(ResetLineKind::Rtc, std::memory_order_release);
    emu_.Get<GuestEngine>().SetResetPending(false);
}

void GuestCpuReset::WatchdogReset() {
    if (latch_) latch_->LatchWatchdogReset();
    pending_kind_.store(ResetLineKind::Other, std::memory_order_release);
    emu_.Get<GuestEngine>().SetResetPending(false);
}

void GuestCpuReset::RegisterResetListener(std::function<void(ResetLineKind)> fn) {
    reset_listeners_.push_back(std::move(fn));
}

void GuestCpuReset::RegisterResetReleaseListener(std::function<void()> fn) {
    release_listeners_.push_back(std::move(fn));
}

void GuestCpuReset::SetPendingResume(bool is_resume) {
    pending_is_resume_.store(is_resume, std::memory_order_release);
}

void GuestCpuReset::SaveState(StateWriter& w) const {
    w.Write<uint32_t>("pending_kind", static_cast<uint32_t>(pending_kind_.load(std::memory_order_acquire)));
    w.Write<uint8_t>("pending_is_resume", pending_is_resume_.load(std::memory_order_acquire) ? 1u : 0u);
}

void GuestCpuReset::RestoreState(StateReader& r) {
    uint32_t kind = 0;
    r.Read("pending_kind", kind);
    if (kind != static_cast<uint32_t>(ResetLineKind::Rtc) &&
        kind != static_cast<uint32_t>(ResetLineKind::Other))
        r.Reject("reset kind %u is not a ResetLineKind", kind);
    pending_kind_.store(static_cast<ResetLineKind>(kind), std::memory_order_release);
    uint8_t resume = 0;
    r.Read("pending_is_resume", resume);
    pending_is_resume_.store(resume != 0, std::memory_order_release);
}

void GuestCpuReset::OnResetDelivered() {
    const ResetLineKind kind =
        pending_kind_.exchange(ResetLineKind::Other, std::memory_order_acq_rel);
    delivered_is_resume_ = pending_is_resume_.exchange(false, std::memory_order_acq_rel);
    for (auto& fn : reset_listeners_) fn(kind);
    emu_.Get<GuestColdBoot>().ExecuteIfPending();
    for (auto& fn : release_listeners_) fn();
}
