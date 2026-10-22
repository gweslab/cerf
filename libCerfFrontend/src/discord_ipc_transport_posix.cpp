#include "discord_ipc_transport.h"

#include <cerfcore/platform/host_descriptor.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace cerffrontend {

namespace {

#ifdef MSG_NOSIGNAL
constexpr int kSendFlags = MSG_NOSIGNAL;
#else
constexpr int kSendFlags = 0;
#endif

const char* RuntimeDir() {
    for (const char* var : {"XDG_RUNTIME_DIR", "TMPDIR", "TMP", "TEMP"})
        if (const char* v = std::getenv(var)) return v;
    return "/tmp";
}

}

struct DiscordIpcTransport::Impl {
    int sock       = -1;
    int stop_read  = -1;
    int stop_write = -1;

    bool WaitReady(short events) {
        pollfd fds[2] = { { sock, events, 0 }, { stop_read, POLLIN, 0 } };
        for (;;) {
            if (poll(fds, 2, -1) < 0) {
                if (errno == EINTR) continue;
                return false;
            }
            if (fds[1].revents) return false;
            if (fds[0].revents) return true;
        }
    }
};

DiscordIpcTransport::DiscordIpcTransport() : impl_(std::make_unique<Impl>()) {
    int fds[2] = { -1, -1 };
    if (pipe(fds) != 0) return;
    if (!cerfcore::host_platform::SetCloseOnExecNonBlocking(fds[0]) ||
        !cerfcore::host_platform::SetCloseOnExecNonBlocking(fds[1])) {
        close(fds[0]);
        close(fds[1]);
        return;
    }
    impl_->stop_read  = fds[0];
    impl_->stop_write = fds[1];
}

DiscordIpcTransport::~DiscordIpcTransport() {
    if (impl_->sock >= 0) close(impl_->sock);
    if (impl_->stop_read >= 0) close(impl_->stop_read);
    if (impl_->stop_write >= 0) close(impl_->stop_write);
}

bool DiscordIpcTransport::Connect(std::string& endpoint) {
    if (impl_->stop_read < 0) return false;
    const char* dir = RuntimeDir();
    for (int i = 0; i < 10; ++i) {
        sockaddr_un addr = {};
        addr.sun_family  = AF_UNIX;
        const int len = std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/discord-ipc-%d", dir, i);
        if (len < 0 || static_cast<size_t>(len) >= sizeof(addr.sun_path)) return false;
        const int s = socket(AF_UNIX, SOCK_STREAM, 0);
        if (s < 0) return false;
#ifdef SO_NOSIGPIPE
        const int on = 1;
        setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
        if (connect(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0 &&
            cerfcore::host_platform::SetCloseOnExecNonBlocking(s)) {
            impl_->sock = s;
            endpoint    = addr.sun_path;
            return true;
        }
        close(s);
    }
    return false;
}

bool DiscordIpcTransport::Write(const uint8_t* buf, size_t len) {
    size_t done = 0;
    while (done < len) {
        if (!impl_->WaitReady(POLLOUT)) return false;
        const ssize_t n = send(impl_->sock, buf + done, len - done, kSendFlags);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            return false;
        }
        done += static_cast<size_t>(n);
    }
    return true;
}

bool DiscordIpcTransport::Read(uint8_t* buf, size_t len) {
    size_t done = 0;
    while (done < len) {
        if (!impl_->WaitReady(POLLIN)) return false;
        const ssize_t n = recv(impl_->sock, buf + done, len - done, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        done += static_cast<size_t>(n);
    }
    return true;
}

void DiscordIpcTransport::RequestStop() {
    if (impl_->stop_write < 0) return;
    const uint8_t one = 1;
    ssize_t       r   = 0;
    do {
        r = write(impl_->stop_write, &one, 1);
    } while (r < 0 && errno == EINTR);
}

}
