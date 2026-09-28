#include "jit_runner.h"

#include "../core/cerf_emulator.h"
#include "../core/fatal.h"
#include "../core/log.h"
#include "../core/rate_probe.h"
#include "../core/virtual_clock.h"
#include "../host/guest_deep_sleep.h"
#include "../peripherals/peripheral_dispatcher.h"
#include "guest_engine.h"
#include "guest_cycle_clock.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <chrono>
#include <intrin.h>

REGISTER_SERVICE(JitRunner);

void JitRunner::OnShutdown() {
    RequestStop();
    Join();
}

JitRunner::~JitRunner() {
    /* If the owner forgot to RequestStop+Join, do it here so the
       std::thread destructor doesn't call terminate(). */
    if (thread_.joinable()) {
        stop_requested_.store(true, std::memory_order_release);
        thread_.join();
    }
}

void JitRunner::Start() {
    if (started_) return;
    /* Hooks run with started_ still false so a restore's JitRunner::Pause
       is a no-op and writes state into the not-yet-running guest. */
    for (auto& h : pre_start_hooks_) h();
    started_ = true;
    thread_ = std::thread([this] { RunLoop(); });
}

void JitRunner::RegisterPreStartHook(std::function<void()> fn) {
    pre_start_hooks_.push_back(std::move(fn));
}

void JitRunner::Join() {
    if (thread_.joinable()) {
        thread_.join();
    }
}

void JitRunner::PublishHostChainExit(const std::unique_lock<std::mutex>&) {
    emu_.Get<GuestEngine>().SetHostChainExit(
        pause_requested_.load(std::memory_order_acquire) ||
        stop_requested_.load(std::memory_order_acquire));
}

void JitRunner::RequestStop() {
    {
        std::unique_lock<std::mutex> lk(pause_mutex_);
        stop_requested_.store(true, std::memory_order_release);
        PublishHostChainExit(lk);
    }
    pause_cv_.notify_all();
}

void JitRunner::Pause() {
    if (!started_) return;
    std::unique_lock<std::mutex> lk(pause_mutex_);
    pause_requested_.store(true, std::memory_order_release);
    PublishHostChainExit(lk);
    pause_cv_.wait(lk, [this] {
        return paused_ || stopped_.load(std::memory_order_acquire);
    });
}

void JitRunner::Resume() {
    {
        std::unique_lock<std::mutex> lk(pause_mutex_);
        pause_requested_.store(false, std::memory_order_release);
        PublishHostChainExit(lk);
    }
    pause_cv_.notify_all();
}

void JitRunner::RunLoop() {
    LOG(Jit, "JitRunner::RunLoop: entered, resolving engine\n");
    /* Resolve the guest engine lazily on the JIT thread - first Get<T> walks the
       OnReady dependency chain. A Get<> in JitRunner::OnReady is service
       pre-warming, forbidden by agent_docs/rules.md. */
    auto& engine = emu_.Get<GuestEngine>();
    auto& fatal  = emu_.Get<Fatal>();
    fatal.SetLiveEngine(&engine);
    LOG(Jit, "JitRunner::RunLoop: engine resolved, entering loop\n");

    /* All boot-time peripherals have registered by now; the engine's physical
       mask is seeded. Catch any peripheral placed above the addressable space
       before a single guest access silently aliases into it. */
    emu_.Get<PeripheralDispatcher>().ValidatePhysReachable(engine.PhysAddrMask());

    auto& vclock     = emu_.Get<VirtualClock>();
    auto& deep_sleep = emu_.Get<GuestDeepSleep>();

#if CERF_DEV_MODE
    auto& probe = emu_.Get<RateProbe>();
#endif

    GuestCycleClock* cycle_clock = emu_.TryGet<GuestCycleClock>();

    bool prev_deep_sleep = false;
    while (!stop_requested_.load(std::memory_order_acquire)) {
#if CERF_DEV_MODE
        const uint64_t t0 = __rdtsc();
        engine.Run();
        probe.AddTsc(RateProbe::TimeCounter::JitRun, __rdtsc() - t0);
        probe.Inc(RateProbe::Counter::JitRuns);
        engine.DispatchTraceIter();
#else
        engine.Run();
#endif
        const bool ds = engine.DeepSleep();
        if (ds != prev_deep_sleep) {
            LOG(SocReset, "[DEEPSLEEP] RunLoop: deep_sleep %d->%d reset_pending=%d pause=%d\n",
                prev_deep_sleep, ds, static_cast<int>(engine.ResetPending()),
                static_cast<int>(pause_requested_.load(std::memory_order_acquire)));
            prev_deep_sleep = ds;
        }
        if (pause_requested_.load(std::memory_order_acquire) || engine.DeepSleep()) {
            if (cycle_clock != nullptr) cycle_clock->OnDispatch();
            std::unique_lock<std::mutex> lk(pause_mutex_);
            paused_ = true;
            vclock.Pause();
            pause_cv_.notify_all();
            LOG(SocReset, "[DEEPSLEEP] RunLoop: park enter ds=%d reset_pending=%d pause=%d pc=0x%08X\n",
                static_cast<int>(engine.DeepSleep()), static_cast<int>(engine.ResetPending()),
                static_cast<int>(pause_requested_.load(std::memory_order_acquire)),
                engine.Pc());
            const bool sleep_park = engine.DeepSleep();
            while (!stop_requested_.load(std::memory_order_acquire) &&
                   !engine.ResetPending() &&
                   (pause_requested_.load(std::memory_order_acquire) || engine.DeepSleep())) {
                int64_t wait_ns = 20000000;
                if (!pause_requested_.load(std::memory_order_acquire) && engine.DeepSleep()) {
                    deep_sleep.PollPark();
                    if (engine.ResetPending() || !engine.DeepSleep()) break;
                    wait_ns = deep_sleep.ParkWaitNs();
                }
                pause_cv_.wait_for(lk, std::chrono::nanoseconds(wait_ns));
            }
            if (sleep_park && !stop_requested_.load(std::memory_order_acquire))
                deep_sleep.FinishPark();
            vclock.Resume();
            paused_ = false;
            LOG(SocReset, "[DEEPSLEEP] RunLoop: park exit ds=%d reset_pending=%d pause=%d pc=0x%08X\n",
                static_cast<int>(engine.DeepSleep()), static_cast<int>(engine.ResetPending()),
                static_cast<int>(pause_requested_.load(std::memory_order_acquire)),
                engine.Pc());
        }
    }

    fatal.SetLiveEngine(nullptr);
    LOG(Boot, "JitRunner: stop requested; thread exiting\n");
    stopped_.store(true, std::memory_order_release);
    { std::lock_guard<std::mutex> lk(pause_mutex_); }
    pause_cv_.notify_all();
}
