#include "qt_show_socket.h"

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

socklen_t ShowSocketAddress(uint32_t pid, sockaddr_un& addr) {
    addr.sun_family = AF_UNIX;
    const int len   = std::snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1, "cerf-show/%u", pid);
    return static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1u + static_cast<size_t>(len));
}

}

int OpenShowSocket(uint32_t pid, int& error) {
    const int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        error = errno;
        return -1;
    }
    sockaddr_un     addr{};
    const socklen_t size = ShowSocketAddress(pid, addr);
    if (bind(fd, reinterpret_cast<const sockaddr*>(&addr), size) != 0) {
        error = errno;
        close(fd);
        return -1;
    }
    return fd;
}

void CloseShowSocket(int fd, uint32_t) { close(fd); }

bool SendShowRequest(uint32_t pid) {
    const int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return false;
    sockaddr_un     addr{};
    const socklen_t size = ShowSocketAddress(pid, addr);
    const bool      sent = sendto(fd, kShowRequest.data(), kShowRequest.size(), 0,
                                  reinterpret_cast<const sockaddr*>(&addr), size) == ssize_t(kShowRequest.size());
    close(fd);
    return sent;
}
