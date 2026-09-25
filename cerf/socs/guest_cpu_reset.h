#pragma once

#include "../core/service.h"
#include "../state/state_stream.h"

#include <atomic>
#include <functional>
#include <vector>

/* Implemented by the SoC peripheral owning the reset-cause register
   (e.g. SA-1110 RCSR). Non-Service so a Peripheral can implement it
   without a Service diamond; the implementer self-registers with
   GuestCpuReset from its OnReady. */
class ResetCauseLatch {
public:
    virtual ~ResetCauseLatch() = default;
    virtual void LatchWarmReset()     = 0;   /* CPU reset, RAM preserved */
    virtual void LatchColdReset()     = 0;   /* CPU reset, RAM lost */
    virtual void LatchWatchdogReset() = 0;   /* watchdog expiry */
};

/* A register's reset value depends on which reset line drove it: the VR41xx register
   tables carry an "RTCRST" row and an "Other resets" row, and they differ (VR4102 UM
   23.2.3: LEDCNTREG RTCRST = 0x0002, other resets "Previous value is retained"). */
enum class ResetLineKind { Rtc, Other };

/* Routes CERF-initiated CPU resets through the SoC's reset-cause latch
   before pending the reset. On cause-tracking SoCs a causeless reset
   hangs the guest: the SA-1110 PPC2002 boot path reads RCSR==0 as
   "sleep exit" and resumes from a stale save block into an UND loop. */
class GuestCpuReset : public Service {
public:
    using Service::Service;

    /* OnReady-time only; at most one latch per emulator instance. */
    void SetCauseLatch(ResetCauseLatch* latch);

    /* Any thread. Host soft reset: RAM survives the reset. */
    void WarmReset();

    /* Any thread. Host hard reset: caller wipes RAM at delivery. */
    void ColdReset();

    /* Any thread. SoC watchdog expiry (e.g. OSMR3 match with OWER.WME=1). */
    void WatchdogReset();

    /* OnReady-time only. Listeners model devices wired to the board's
       reset line (RESET_OUT): they run at reset delivery on the JIT
       thread, for every delivered reset regardless of source. */
    void RegisterResetListener(std::function<void(ResetLineKind)> fn);
    void RegisterResetReleaseListener(std::function<void()> fn);

    void SetPendingResume(bool is_resume);

    /* JIT thread, reset-delivery branch only: runs the reset-line
       listeners, then an armed GuestColdBoot hard reset. */
    void OnResetDelivered();

    bool DeliveredResetWasResume() const { return delivered_is_resume_; }

    void SaveState(StateWriter& w) const;
    void RestoreState(StateReader& r);

private:
    ResetCauseLatch*                                latch_ = nullptr;
    std::vector<std::function<void(ResetLineKind)>> reset_listeners_;
    std::vector<std::function<void()>>              release_listeners_;
    std::atomic<ResetLineKind>                      pending_kind_{ResetLineKind::Other};
    std::atomic<bool>                               pending_is_resume_{false};
    bool                                            delivered_is_resume_ = false;
};
