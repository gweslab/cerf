#include "process_watch.h"

#include "../../uninstaller-win32/process_wait.h"

#include <QDir>

bool WaitForProcessExit(uint32_t pid, int timeout_ms, QString& error) {
    std::wstring failure;
    if (process_wait::WaitForPidExit(pid, uint32_t(timeout_ms), failure)) return true;
    error = QString::fromStdWString(failure);
    return false;
}

bool ProcessesRunningImage(const QString& executable_path, std::vector<uint32_t>& pids, QString& error) {
    std::wstring failure;
    if (process_wait::ProcessesRunningImage(QDir::toNativeSeparators(executable_path).toStdWString(), pids, failure))
        return true;
    error = QString::fromStdWString(failure);
    return false;
}
