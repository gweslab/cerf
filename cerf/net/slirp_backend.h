#pragma once

#include "network_backend.h"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

struct Slirp;
struct SlirpCb;      /* libslirp callback vtable; heap-allocated so the
                        pointer libslirp stores stays valid for our lifetime */
struct SlirpTimer;

class SlirpBackend : public NetworkBackend {
public:
    using NetworkBackend::NetworkBackend;

    bool ShouldRegister() override;
    void OnReady() override;    /* construct libslirp + start thread */
    void OnShutdown() override;

    ~SlirpBackend() override;

    void SendFrame(const uint8_t* frame, std::size_t len) override;

    /* libslirp's built-in ICMP path relies on SOCK_RAW, which a non-admin process
       cannot open on Windows (WSAEACCES -> silent ping failure), so echo requests are
       intercepted before slirp_input and serviced with the unprivileged IcmpSendEcho. */
    bool TryInterceptIcmpEcho(const uint8_t* frame, std::size_t len);

    bool TryInterceptAaaaQuery(const uint8_t* frame, std::size_t len);
    cerf::inet::MacAddress GuestMacAddress() const override;

    /* Implementation hooks for the C callbacks libslirp invokes. Public so
       the static C-shim functions in the .cpp can call them; do not call
       these from outside the .cpp. */
    void OnSlirpSendPacket(const void* buf, std::size_t len);
    int64_t OnSlirpClockGetNs();
    SlirpTimer* OnSlirpTimerNew(void (*cb)(void* opaque), void* cb_opaque);
    void OnSlirpTimerFree(SlirpTimer* t);
    void OnSlirpTimerMod(SlirpTimer* t, int64_t expire_ms);
    void OnSlirpNotify();

private:
    void PollLoop();
    void StopPollThread();
    void JoinIcmpThreads();
    int64_t NowMs() const;

    cerf::inet::MacAddress guest_mac_{};
    uint32_t mtu_ = 1500;
    bool host_has_v6_ = false;        /* set by IPv6 reachability probe in OnInit */

    Slirp* slirp_ = nullptr;
    SlirpCb* cbs_ = nullptr;
    std::mutex slirp_mutex_;          /* serializes ALL libslirp calls */

    std::thread poll_thread_;

    struct IcmpEcho {
        std::thread                            thread;
        std::shared_ptr<std::atomic<bool>>     done;
    };
    std::mutex             icmp_mutex_;
    std::vector<IcmpEcho>  icmp_threads_;
    bool                   icmp_stopping_ = false;

    std::atomic<bool> stop_{false};
    std::mutex notify_mutex_;
    std::condition_variable notify_cv_;
    bool notified_ = false;

    std::mutex timers_mutex_;
    std::vector<std::unique_ptr<SlirpTimer>> timers_;
};
