#pragma once

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

#include "../core/service.h"

class JitRunner : public Service {
public:
    using Service::Service;
    ~JitRunner() override;

    void OnShutdown() override;

    /* Spawn the JIT thread. Idempotent: subsequent calls are no-ops. */
    void Start();

    /* Run fn on the calling (main) thread inside Start(), after Bootstrap
       (so every service is ready) but before the JIT thread spawns. For
       boot-time actions that must precede guest execution. Register from
       OnReady. */
    void RegisterPreStartHook(std::function<void()> fn);

    /* Block until the JIT thread terminates. Caller is expected to
       arrange termination (RequestStop or process exit) before
       calling - Join itself does NOT signal stop. */
    void Join();

    /* Cooperative stop signal. The thread checks this between
       ArmJit::Run() iterations and exits when set. Safe to call
       from any thread. */
    void RequestStop();

    /* True once the JIT thread has left RunLoop. Lets a closing UI thread
       poll for a clean CPU stop after RequestStop without blocking on Join. */
    bool Stopped() const { return stopped_.load(std::memory_order_acquire); }

    bool Started() const { return started_.load(std::memory_order_acquire); }

    /* Host thread only - calling from the JIT thread self-deadlocks.
       Returns once the guest CPU is parked between blocks. */
    void Pause();
    void Resume();

private:
    void PublishHostChainExit(const std::unique_lock<std::mutex>&);

    void RunLoop();

    std::thread             thread_;
    std::atomic<bool>       stop_requested_{false};
    std::atomic<bool>       stopped_{false};
    std::atomic<bool>       started_{false};

    std::atomic<bool>       pause_requested_{false};
    bool                    paused_ = false;          /* guarded by pause_mutex_ */
    std::mutex              pause_mutex_;
    std::condition_variable pause_cv_;

    std::vector<std::function<void()>> pre_start_hooks_;
};
