#include "qt_show_socket.h"

#include <cerfcore/platform/host_descriptor.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

bool ShowSocketPath(uint32_t pid, sockaddr_un& addr) {
    const char* dir = std::getenv("TMPDIR");
    if (dir == nullptr || dir[0] == '\0') dir = "/tmp/";
    const size_t length = std::char_traits<char>::length(dir);
    const char*  slash  = dir[length - 1] == '/' ? "" : "/";
    const int    len    = std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s%scerf-show-%u", dir,
                                        slash, pid);
    return len > 0 && static_cast<size_t>(len) < sizeof(addr.sun_path);
}

}

int OpenShowSocket(uint32_t pid, int& error) {
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (!ShowSocketPath(pid, addr)) {
        error = ENAMETOOLONG;
        return -1;
    }
    const int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        error = errno;
        return -1;
    }
    if (!cerfcore::host_platform::SetCloseOnExecNonBlocking(fd)) {
        error = errno;
        close(fd);
        return -1;
    }
    unlink(addr.sun_path);
    if (bind(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        error = errno;
        close(fd);
        return -1;
    }
    return fd;
}

void CloseShowSocket(int fd, uint32_t pid) {
    close(fd);
    sockaddr_un addr{};
    if (ShowSocketPath(pid, addr)) unlink(addr.sun_path);
}
