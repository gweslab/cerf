#include "process_watch.h"

#include "filesystem_path.h"

#include <cerfcore/platform/host_error.h>

#include <QDir>
#include <QFile>
#include <QFileInfo>

#include <poll.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>

namespace {

char ProcessState(uint32_t pid) {
    QFile stat(QStringLiteral("/proc/%1/stat").arg(pid));
    if (!stat.open(QIODevice::ReadOnly)) return '\0';
    const QByteArray text  = stat.readAll();
    const qsizetype  close = text.lastIndexOf(')');
    if (close < 0 || close + 2 >= text.size()) return '\0';
    return text.at(close + 2);
}

bool ProcessAlive(uint32_t pid) {
    const char state = ProcessState(pid);
    return state != '\0' && state != 'Z' && state != 'X';
}

}

bool WaitForProcessExit(uint32_t pid, int timeout_ms, QString& error) {
    const int fd = int(syscall(SYS_pidfd_open, pid_t(pid), 0u));
    if (fd < 0) {
        const int code = errno;
        if (code == ESRCH) return true;
        error = QStringLiteral("cannot watch process %1 (%2)")
                    .arg(pid)
                    .arg(QString::fromStdString(cerfcore::host_platform::ErrorText(uint32_t(code))));
        return false;
    }
    pollfd watch{fd, POLLIN, 0};
    int    ready = 0;
    do {
        ready = poll(&watch, 1, timeout_ms);
    } while (ready < 0 && errno == EINTR);
    const int code = errno;
    close(fd);
    if (ready > 0) return true;
    if (ready < 0)
        error = QStringLiteral("cannot wait for process %1 (%2)")
                    .arg(pid)
                    .arg(QString::fromStdString(cerfcore::host_platform::ErrorText(uint32_t(code))));
    return false;
}

bool ProcessesRunningImage(const QString& executable_path, std::vector<uint32_t>& pids, QString& error) {
    pids.clear();
    const QDir proc(QStringLiteral("/proc"));
    if (!EntryExists(PathOf(proc.path()))) {
        error = QStringLiteral("cannot enumerate running processes (/proc is missing)");
        return false;
    }
    const QString wanted = QFileInfo(executable_path).canonicalFilePath();
    const QString self   = QString::number(getpid());
    for (const QString& entry : proc.entryList(QDir::Dirs | QDir::NoDotAndDotDot)) {
        bool           numeric = false;
        const uint32_t pid     = entry.toUInt(&numeric);
        if (!numeric || entry == self) continue;
        const QString image = QFileInfo(QStringLiteral("/proc/%1/exe").arg(entry)).symLinkTarget();
        if (!image.isEmpty() && image == wanted && ProcessAlive(pid)) pids.push_back(pid);
    }
    return true;
}
