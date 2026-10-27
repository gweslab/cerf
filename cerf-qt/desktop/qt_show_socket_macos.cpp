#include "qt_show_socket.h"

#include <cerfcore/core/log.h>
#include <cerfcore/core/path_split.h>
#include <cerfcore/platform/host_descriptor.h>
#include <cerfcore/platform/host_error.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <signal.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

constexpr std::string_view kShowSocketPrefix = "cerf-show-";

std::string ShowSocketDirectory() {
    const char* dir = std::getenv("TMPDIR");
    return dir == nullptr || dir[0] == '\0' ? "/tmp/" : dir;
}

std::string ShowSocketFile(const std::string& directory, const std::string& name) {
    return cerfcore::AppendPathName(directory, name, cerfcore::kPosixPathSeparators<char>);
}

void RemoveSocketFile(const char* path) {
    if (unlink(path) == 0 || errno == ENOENT) return;
    const uint32_t error = static_cast<uint32_t>(errno);
    LOG(Caution, "show socket %s not removed: %s\n", path, cerfcore::host_platform::ErrorText(error).c_str());
}

bool ShowSocketPath(uint32_t pid, sockaddr_un& addr) {
    const std::string path =
        ShowSocketFile(ShowSocketDirectory(), std::string(kShowSocketPrefix) + std::to_string(pid));
    if (path.size() >= sizeof(addr.sun_path)) return false;
    std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
    return true;
}

void RemoveDeadShowSockets() {
    const std::string directory = ShowSocketDirectory();
    DIR*              listing   = opendir(directory.c_str());
    if (listing == nullptr) return;
    while (const dirent* entry = readdir(listing)) {
        const std::string_view name(entry->d_name);
        if (name.substr(0, kShowSocketPrefix.size()) != kShowSocketPrefix) continue;
        const char* digits = entry->d_name + kShowSocketPrefix.size();
        char*       end    = nullptr;
        const long  pid    = std::strtol(digits, &end, 10);
        if (end == digits || *end != '\0' || pid <= 0) continue;
        if (kill(pid_t(pid), 0) == 0 || errno != ESRCH) continue;
        RemoveSocketFile(ShowSocketFile(directory, std::string(name)).c_str());
    }
    closedir(listing);
}

}

int OpenShowSocket(uint32_t pid, int& error) {
    RemoveDeadShowSockets();
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
    RemoveSocketFile(addr.sun_path);
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
    if (ShowSocketPath(pid, addr)) RemoveSocketFile(addr.sun_path);
}

bool SendShowRequest(uint32_t pid) {
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (!ShowSocketPath(pid, addr)) return false;
    const int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    cerfcore::host_platform::SetCloseOnExec(fd);
    const bool sent = sendto(fd, kShowRequest.data(), kShowRequest.size(), 0, reinterpret_cast<const sockaddr*>(&addr),
                             sizeof(addr)) == ssize_t(kShowRequest.size());
    close(fd);
    return sent;
}
