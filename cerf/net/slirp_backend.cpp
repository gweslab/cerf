#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
/* libslirp.h is built as a static archive by vcpkg (manifest mode picks
   the project triplet — currently x86-windows-static). Tell the header
   to declare exports as plain symbols rather than __declspec(dllimport). */
#define LIBSLIRP_STATIC

/* winsock2.h MUST come before any windows.h include (it defines socket types
   that windows.h's older winsock.h would re-declare with conflicting types).
   libslirp.h itself pulls in <windows.h>, so we include winsock2 first. */
#include <winsock2.h>
#include <ws2tcpip.h>

#include <slirp/libslirp.h>

#include "slirp_backend.h"
#include "slirp_backend_internal.h"
#include "slirp_poll_shim.h"
#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../core/log.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>

/* SlirpTimer — what we hand back to libslirp from timer_new. libslirp
   treats it as opaque. We store the callback + arm time. The poll loop
   walks the timer list each iteration and fires anything whose expire
   time has passed. */
struct SlirpTimer {
    void (*cb)(void* opaque) = nullptr;
    void* cb_opaque = nullptr;
    /* expire_ms is the absolute deadline in our NowMs() time base.
       INT64_MAX = disarmed. */
    int64_t expire_ms = (std::numeric_limits<int64_t>::max)();
};

namespace {

std::array<uint8_t, 6> ParseMac(const std::string& s) {
    std::array<uint8_t, 6> out{};
    unsigned bytes[6] = {};
    int n = std::sscanf(s.c_str(),
                        "%02X:%02X:%02X:%02X:%02X:%02X",
                        &bytes[0], &bytes[1], &bytes[2],
                        &bytes[3], &bytes[4], &bytes[5]);
    if (n != 6) {
        LOG(Caution, "FATAL: malformed network_mac='%s' (need XX:XX:XX:XX:XX:XX)\n",
                s.c_str());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)bytes[i];
    return out;
}

/* libslirp fixed network — 10.0.2.0/24, host 10.0.2.2, dhcp 10.0.2.15,
   dns 10.0.2.3. These are libslirp's documented defaults; matching them
   keeps the DHCP/ARP/DNS responder behavior predictable. */
in_addr MakeAddr(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    in_addr r{};
    r.S_un.S_un_b.s_b1 = a;
    r.S_un.S_un_b.s_b2 = b;
    r.S_un.S_un_b.s_b3 = c;
    r.S_un.S_un_b.s_b4 = d;
    return r;
}

in6_addr MakeAddr6(uint16_t a, uint16_t b, uint16_t c, uint16_t d,
                   uint16_t e, uint16_t f, uint16_t g, uint16_t h) {
    in6_addr r{};
    auto put = [&](size_t i, uint16_t v) {
        r.u.Byte[2 * i]     = (uint8_t)(v >> 8);
        r.u.Byte[2 * i + 1] = (uint8_t)(v & 0xFF);
    };
    put(0, a); put(1, b); put(2, c); put(3, d);
    put(4, e); put(5, f); put(6, g); put(7, h);
    return r;
}

/* C-shims that bounce SlirpCb pointers into SlirpBackend instance methods.
   Signatures match libslirp 4.9.1 (SLIRP_CONFIG_VERSION_MAX=6) — note
   slirp_ssize_t for SlirpWriteCb (typedef'd to SSIZE_T on Windows). */
slirp_ssize_t cb_send_packet(const void* buf, size_t len, void* opaque) {
    static_cast<SlirpBackend*>(opaque)->OnSlirpSendPacket(buf, len);
    return (slirp_ssize_t)len;
}
void cb_guest_error(const char* msg, void* /*opaque*/) {
    LOG(Net, "libslirp guest_error: %s\n", msg ? msg : "(null)");
}
int64_t cb_clock_get_ns(void* opaque) {
    return static_cast<SlirpBackend*>(opaque)->OnSlirpClockGetNs();
}
void* cb_timer_new(SlirpTimerCb cb, void* cb_opaque, void* opaque) {
    return static_cast<SlirpBackend*>(opaque)->OnSlirpTimerNew(cb, cb_opaque);
}
void cb_timer_free(void* timer, void* opaque) {
    static_cast<SlirpBackend*>(opaque)->OnSlirpTimerFree(static_cast<SlirpTimer*>(timer));
}
void cb_timer_mod(void* timer, int64_t expire_time, void* opaque) {
    static_cast<SlirpBackend*>(opaque)->OnSlirpTimerMod(static_cast<SlirpTimer*>(timer), expire_time);
}
void cb_notify(void* opaque) {
    static_cast<SlirpBackend*>(opaque)->OnSlirpNotify();
}
/* libslirp v4 callbacks (deprecated since v6, replaced by *_socket variants
   below). With cfg.version=6 these never fire on Win64 — present only so
   libslirp's null-pointer checks pass and any internal fallback paths work. */
void cb_register_poll_fd(int /*fd*/, void* /*opaque*/) { /* no-op */ }
void cb_unregister_poll_fd(int /*fd*/, void* /*opaque*/) { /* no-op */ }
/* libslirp v6 socket-aware variants — slirp_os_socket = SOCKET on Windows
   (full 64-bit on x64). We don't track the set internally; the poll thread
   re-collects fds via slirp_pollfds_fill_socket every iteration. */
void cb_register_poll_socket(slirp_os_socket /*s*/, void* /*opaque*/) { /* no-op */ }
void cb_unregister_poll_socket(slirp_os_socket /*s*/, void* /*opaque*/) { /* no-op */ }

} /* namespace */

/* Consulted by OnReady to decide whether libslirp should act as the
   guest's IPv6 default router and whether AAAA DNS responses should
   pass through to the guest. */
bool ProbeHostIpv6Reachable();

bool SlirpBackend::ShouldRegister() {
    return emu_.Get<DeviceConfig>().network_enabled;
}

void SlirpBackend::OnReady() {
    auto& cfg = emu_.Get<DeviceConfig>();
    guest_mac_ = ParseMac(cfg.network_mac);
    mtu_ = cfg.network_mtu;

    /* WSAStartup once per process — safe to call repeatedly; ref-counted. */
    WSADATA wsa{};
    int wsa_rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (wsa_rc != 0) {
        LOG(Caution, "FATAL: WSAStartup failed (%d)\n", wsa_rc);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    host_has_v6_ = ProbeHostIpv6Reachable();
    bool host_has_v6 = host_has_v6_;

    SlirpConfig sc{};
    sc.version = SLIRP_CONFIG_VERSION_MAX;   /* 6 in libslirp 4.9.1 */
    sc.restricted = 0;
    sc.in_enabled = true;
    sc.vnetwork    = MakeAddr(10, 0, 2, 0);
    sc.vnetmask    = MakeAddr(255, 255, 255, 0);
    sc.vhost       = MakeAddr(10, 0, 2, 2);
    sc.in6_enabled    = host_has_v6;
    sc.vprefix_addr6  = MakeAddr6(0xFEC0, 0, 0, 0, 0, 0, 0, 0);
    sc.vprefix_len    = 64;
    sc.vhost6         = MakeAddr6(0xFEC0, 0, 0, 0, 0, 0, 0, 2);
    sc.vnameserver6   = MakeAddr6(0xFEC0, 0, 0, 0, 0, 0, 0, 3);
    sc.vhostname   = "cerf";
    sc.tftp_server_name = nullptr;
    sc.tftp_path        = nullptr;
    sc.bootfile         = nullptr;
    sc.vdhcp_start      = MakeAddr(10, 0, 2, 15);
    sc.vnameserver      = MakeAddr(10, 0, 2, 3);
    sc.vdnssearch       = nullptr;
    sc.vdomainname      = nullptr;
    sc.if_mtu           = mtu_;
    sc.if_mru           = mtu_;
    sc.disable_host_loopback = false;
    sc.enable_emu       = false;
    sc.outbound_addr    = nullptr;
    sc.outbound_addr6   = nullptr;
    sc.disable_dns      = false;
    sc.disable_dhcp     = false;
    /* v5+ fields — zero-init via SlirpConfig sc{}; left explicit for clarity. */
    sc.mfr_id           = 0;
    /* sc.oob_eth_addr already zeroed by sc{}. */

    cbs_ = new SlirpCb{};
    cbs_->send_packet              = &cb_send_packet;
    cbs_->guest_error              = &cb_guest_error;
    cbs_->clock_get_ns             = &cb_clock_get_ns;
    cbs_->timer_new                = &cb_timer_new;
    cbs_->timer_free               = &cb_timer_free;
    cbs_->timer_mod                = &cb_timer_mod;
    cbs_->register_poll_fd         = &cb_register_poll_fd;     /* deprecated */
    cbs_->unregister_poll_fd       = &cb_unregister_poll_fd;   /* deprecated */
    cbs_->notify                   = &cb_notify;
    /* init_completed and timer_new_opaque — v4+ callbacks; libslirp null-
       checks both before calling (confirmed from slirp.c 4.9.1: `if
       (slirp->cfg_version >= 4 && slirp->cb->init_completed)`). nullptr
       is safe here. */
    cbs_->init_completed           = nullptr;
    cbs_->timer_new_opaque         = nullptr;
    /* v6+ socket-aware poll-fd registration. */
    cbs_->register_poll_socket     = &cb_register_poll_socket;
    cbs_->unregister_poll_socket   = &cb_unregister_poll_socket;

    {
        std::lock_guard<std::mutex> lk(slirp_mutex_);
        slirp_ = slirp_new(&sc, cbs_, this);
    }
    if (!slirp_) {
        LOG(Caution, "FATAL: slirp_new returned null\n");
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    LOG(Net, "SlirpBackend ready: guest=%02X:%02X:%02X:%02X:%02X:%02X "
             "v4=10.0.2.0/24 host=10.0.2.2 dhcp=10.0.2.15 dns=10.0.2.3 "
             "v6=%s mtu=%u\n",
        guest_mac_[0], guest_mac_[1], guest_mac_[2],
        guest_mac_[3], guest_mac_[4], guest_mac_[5],
        host_has_v6 ? "fec0::/64 host6=fec0::2 dns6=fec0::3"
                    : "LAN-router off (host has no v6 internet — guest stays link-local)",
        mtu_);

    auto register_forwards = [&](const std::string& spec, int is_udp,
                                 const char* proto_name) {
        if (spec.empty()) return;
        in_addr host_addr  = MakeAddr(127, 0, 0, 1);
        in_addr guest_addr = MakeAddr(10, 0, 2, 15);
        size_t pos = 0;
        while (pos < spec.size()) {
            size_t comma = spec.find(',', pos);
            std::string tok = spec.substr(pos, comma - pos);
            pos = (comma == std::string::npos) ? spec.size() : comma + 1;
            size_t colon = tok.find(':');
            if (colon == std::string::npos) {
                LOG(Caution, "bad %s forward '%s' — expected HOST_PORT:GUEST_PORT\n",
                        proto_name, tok.c_str());
                continue;
            }
            int host_port  = std::atoi(tok.substr(0, colon).c_str());
            int guest_port = std::atoi(tok.substr(colon + 1).c_str());
            if (host_port <= 0 || host_port > 65535 ||
                guest_port <= 0 || guest_port > 65535) {
                LOG(Caution, "bad %s forward '%s' — port out of range\n",
                        proto_name, tok.c_str());
                continue;
            }
            std::lock_guard<std::mutex> lk(slirp_mutex_);
            int rc = slirp_add_hostfwd(slirp_, is_udp, host_addr, host_port,
                                       guest_addr, guest_port);
            if (rc != 0) {
                LOG(Caution, "slirp_add_hostfwd %s 127.0.0.1:%d -> 10.0.2.15:%d "
                        "failed (rc=%d)\n", proto_name, host_port, guest_port, rc);
            } else {
                LOG(Net, "forward %s 127.0.0.1:%d -> 10.0.2.15:%d\n",
                    proto_name, host_port, guest_port);
            }
        }
    };
    register_forwards(cfg.network_forward_tcp, 0, "TCP");
    register_forwards(cfg.network_forward_udp, 1, "UDP");

    poll_thread_ = std::thread(&SlirpBackend::PollLoop, this);
}

SlirpBackend::~SlirpBackend() {
    stop_.store(true, std::memory_order_release);
    OnSlirpNotify();
    if (poll_thread_.joinable()) poll_thread_.join();
    if (slirp_) {
        std::lock_guard<std::mutex> lk(slirp_mutex_);
        slirp_cleanup(slirp_);
        slirp_ = nullptr;
    }
    delete cbs_;
    cbs_ = nullptr;
}

void SlirpBackend::SendFrame(const uint8_t* frame, std::size_t len) {
    if (!slirp_ || !frame || len == 0) return;
    {
        static std::atomic<uint64_t> tx_count{0};
        uint64_t n = tx_count.fetch_add(1, std::memory_order_relaxed) + 1;
        char tag[128] = {};
        ClassifyFrame(frame, len, tag, sizeof(tag));
        LOG(Net, "TX #%llu len=%zu %s\n",
            (unsigned long long)n, len, tag);
    }
    if (TryInterceptIcmpEcho(frame, len)) return;
    /* AAAA strip — when the host has no IPv6 internet, reply to AAAA
       queries with NoData so the guest never gets unreachable AAAA
       records and wastes time on NS/SYN to them; pass everything else
       through. */
    if (TryInterceptAaaaQuery(frame, len)) return;
    std::lock_guard<std::mutex> lk(slirp_mutex_);
    slirp_input(slirp_, frame, (int)len);
}

void SlirpBackend::SetReceiveCallback(RxFn cb) {
    std::lock_guard<std::mutex> lk(rx_cb_mutex_);
    rx_cb_ = std::move(cb);
}

std::array<uint8_t, 6> SlirpBackend::GuestMacAddress() const {
    return guest_mac_;
}

std::array<uint8_t, 6> SlirpBackend::HostGatewayMacAddress() const {
    return {0x52, 0x55, 0x0A, 0x00, 0x02, 0x02};
}

void SlirpBackend::OnSlirpSendPacket(const void* buf, std::size_t len) {
    /* Called from PollLoop under slirp_mutex_. Hand the frame to the
       installed RX callback; the consumer (NDIS miniport) is responsible
       for copying out before returning. */
    RxFn cb;
    {
        std::lock_guard<std::mutex> lk(rx_cb_mutex_);
        cb = rx_cb_;
    }
    static std::atomic<uint64_t> rx_count{0};
    uint64_t n = rx_count.fetch_add(1, std::memory_order_relaxed) + 1;
    char tag[128] = {};
    ClassifyFrame(static_cast<const uint8_t*>(buf), len, tag, sizeof(tag));
    LOG(Net, "RX #%llu len=%zu %s\n",
        (unsigned long long)n, len, tag);
    if (cb) cb(static_cast<const uint8_t*>(buf), len);
}

int64_t SlirpBackend::OnSlirpClockGetNs() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

SlirpTimer* SlirpBackend::OnSlirpTimerNew(void (*cb)(void* opaque), void* cb_opaque) {
    auto t = std::make_unique<SlirpTimer>();
    t->cb = cb;
    t->cb_opaque = cb_opaque;
    t->expire_ms = (std::numeric_limits<int64_t>::max)();
    SlirpTimer* raw = t.get();
    std::lock_guard<std::mutex> lk(timers_mutex_);
    timers_.push_back(std::move(t));
    return raw;
}

void SlirpBackend::OnSlirpTimerFree(SlirpTimer* t) {
    std::lock_guard<std::mutex> lk(timers_mutex_);
    timers_.erase(std::remove_if(timers_.begin(), timers_.end(),
                                 [t](const std::unique_ptr<SlirpTimer>& p) {
                                     return p.get() == t;
                                 }),
                  timers_.end());
}

void SlirpBackend::OnSlirpTimerMod(SlirpTimer* t, int64_t expire_ms) {
    /* libslirp passes the absolute time in our clock_get_ns base, but as
       milliseconds. Store as-is; PollLoop compares against NowMs(). */
    std::lock_guard<std::mutex> lk(timers_mutex_);
    if (t) t->expire_ms = expire_ms;
    /* Wake the poll thread so it re-examines the timer set immediately. */
    OnSlirpNotify();
}

void SlirpBackend::OnSlirpNotify() {
    {
        std::lock_guard<std::mutex> lk(notify_mutex_);
        notified_ = true;
    }
    notify_cv_.notify_one();
}

int64_t SlirpBackend::NowMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void SlirpBackend::PollLoop() {
    constexpr uint32_t MAX_TIMEOUT_MS = 1000;
    std::vector<WSAPOLLFD> fds;
    LOG(Net, "SlirpBackend poll thread started (tid=%u)\n",
        (unsigned)GetCurrentThreadId());

    while (!stop_.load(std::memory_order_acquire)) {
        fds.clear();
        uint32_t timeout_ms = MAX_TIMEOUT_MS;

        /* Step 1 — fill pollfd set (socket-aware v6 API so SOCKET handles
           reach our add-poll callback at full Win64 width). */
        {
            std::lock_guard<std::mutex> lk(slirp_mutex_);
            PollFillCtx ctx{&fds};
            slirp_pollfds_fill_socket(slirp_, &timeout_ms, &cb_add_poll_socket, &ctx);
        }

        /* Step 2 — clamp timeout to the earliest pending timer. */
        {
            std::lock_guard<std::mutex> lk(timers_mutex_);
            int64_t now = NowMs();
            for (auto& t : timers_) {
                if (t->expire_ms == (std::numeric_limits<int64_t>::max)()) continue;
                int64_t dt = t->expire_ms - now;
                if (dt <= 0) { timeout_ms = 0; break; }
                if ((uint32_t)dt < timeout_ms) timeout_ms = (uint32_t)dt;
            }
        }

        /* Step 3 — block on the registered fds, capped by timeout. */
        int npoll = 0;
        if (!fds.empty()) {
            npoll = WSAPoll(fds.data(), (ULONG)fds.size(),
                            (int)((std::min<uint32_t>)(timeout_ms, INT_MAX)));
        } else {
            std::unique_lock<std::mutex> lk(notify_mutex_);
            notify_cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                                [this] { return notified_ || stop_.load(); });
            notified_ = false;
        }
        if (stop_.load(std::memory_order_acquire)) break;

        /* Step 4 — let libslirp consume any ready fds. */
        {
            std::lock_guard<std::mutex> lk(slirp_mutex_);
            PollFillCtx ctx{&fds};
            slirp_pollfds_poll(slirp_, npoll < 0 ? 1 : 0, &cb_get_revents, &ctx);
        }

        /* Step 5 — fire any expired timers (outside the timers_ lock). */
        std::vector<SlirpTimer*> due;
        {
            std::lock_guard<std::mutex> lk(timers_mutex_);
            int64_t now = NowMs();
            for (auto& t : timers_) {
                if (t->expire_ms != (std::numeric_limits<int64_t>::max)() &&
                    t->expire_ms <= now) {
                    due.push_back(t.get());
                    /* Disarm; libslirp re-mods if it wants to re-fire. */
                    t->expire_ms = (std::numeric_limits<int64_t>::max)();
                }
            }
        }
        for (auto* t : due) {
            std::lock_guard<std::mutex> lk(slirp_mutex_);
            if (t->cb) t->cb(t->cb_opaque);
        }
    }
}

REGISTER_SERVICE_AS(SlirpBackend, NetworkBackend);
