#include "process_watch.h"

#include <cerfcore/platform/host_error.h>

#include <QFileInfo>

#include <libproc.h>
#include <sys/event.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <unistd.h>

#include <cerrno>
#include <vector>

namespace {

bool ProcessAlive(uint32_t pid) {
    struct proc_bsdinfo info {};
    const int size = proc_pidinfo(int(pid), PROC_PIDTBSDINFO, 0, &info, int(sizeof(info)));
    if (size <= 0) return errno != ESRCH;
    return info.pbi_status != SZOMB;
}

}

bool WaitForProcessExit(uint32_t pid, int timeout_ms, QString& error) {
    const int queue = kqueue();
    if (queue < 0) {
        error = QStringLiteral("cannot watch process %1 (%2)")
                    .arg(pid)
                    .arg(QString::fromStdString(cerfcore::host_platform::ErrorText(uint32_t(errno))));
        return false;
    }
    struct kevent change {};
    EV_SET(&change, uintptr_t(pid), EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, nullptr);
    if (kevent(queue, &change, 1, nullptr, 0, nullptr) < 0) {
        const int code = errno;
        close(queue);
        if (code == ESRCH) return true;
        error = QStringLiteral("cannot watch process %1 (%2)")
                    .arg(pid)
                    .arg(QString::fromStdString(cerfcore::host_platform::ErrorText(uint32_t(code))));
        return false;
    }
    if (!ProcessAlive(pid)) {
        close(queue);
        return true;
    }
    const timespec timeout{timeout_ms / 1000, long(timeout_ms % 1000) * 1000000L};
    struct kevent  event {};
    int            ready = 0;
    do {
        ready = kevent(queue, nullptr, 0, &event, 1, &timeout);
    } while (ready < 0 && errno == EINTR);
    const int code = errno;
    close(queue);
    if (ready > 0) return true;
    if (ready < 0)
        error = QStringLiteral("cannot wait for process %1 (%2)")
                    .arg(pid)
                    .arg(QString::fromStdString(cerfcore::host_platform::ErrorText(uint32_t(code))));
    return false;
}

bool ProcessesRunningImage(const QString& executable_path, std::vector<uint32_t>& pids, QString& error) {
    pids.clear();
    const QString wanted = QFileInfo(executable_path).canonicalFilePath();
    const int     count  = proc_listallpids(nullptr, 0);
    if (count <= 0) {
        error = QStringLiteral("cannot enumerate running processes (%1)")
                    .arg(QString::fromStdString(cerfcore::host_platform::ErrorText(uint32_t(errno))));
        return false;
    }
    std::vector<pid_t> all(size_t(count) + 64);
    const int          listed = proc_listallpids(all.data(), int(all.size() * sizeof(pid_t)));
    if (listed <= 0) {
        error = QStringLiteral("cannot enumerate running processes (%1)")
                    .arg(QString::fromStdString(cerfcore::host_platform::ErrorText(uint32_t(errno))));
        return false;
    }
    for (int i = 0; i < listed; ++i) {
        const pid_t pid = all[size_t(i)];
        if (pid <= 0 || pid == getpid()) continue;
        char path[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(pid, path, sizeof(path)) <= 0) continue;
        if (QFileInfo(QString::fromUtf8(path)).canonicalFilePath() == wanted && ProcessAlive(uint32_t(pid)))
            pids.push_back(uint32_t(pid));
    }
    return true;
}
