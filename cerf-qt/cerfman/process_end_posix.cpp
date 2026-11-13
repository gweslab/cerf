#include "process_end.h"

#include <cerfcore/platform/host_error.h>

#include <signal.h>

#include <cerrno>

bool EndProcess(uint32_t pid, QString& error) {
    if (kill(pid_t(pid), SIGKILL) == 0 || errno == ESRCH) return true;
    error = QStringLiteral("cannot end process %1 (%2)")
                .arg(pid)
                .arg(QString::fromStdString(cerfcore::host_platform::ErrorText(uint32_t(errno))));
    return false;
}
