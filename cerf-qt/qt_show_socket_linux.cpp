#include "qt_show_socket.h"

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int OpenShowSocket(uint32_t pid, int& error) {
    const int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        error = errno;
        return -1;
    }
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    const int len   = std::snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1, "cerf-show/%u", pid);
    const socklen_t size = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1u +
                                                  static_cast<size_t>(len));
    if (bind(fd, reinterpret_cast<const sockaddr*>(&addr), size) != 0) {
        error = errno;
        close(fd);
        return -1;
    }
    return fd;
}

void CloseShowSocket(int fd, uint32_t) { close(fd); }
