#include "emulator_raise.h"

#include "../cerfman/process_watch.h"
#include "qt_show_socket.h"

#include <cerfcore/core/log.h>
#include <cerfcore/platform/host_process.h>

#include <QString>

#include <algorithm>

bool RaiseEmulatorWindow(const RunningStatus& status) {
    if (status.pid == 0) return false;
    std::vector<uint32_t> pids;
    QString               error;
    if (!ProcessesRunningImage(QString::fromStdString(cerfcore::host_platform::ExecutablePath()), pids, error)) {
        LOG(Manager, "RaiseEmulatorWindow: %s\n", qUtf8Printable(error));
        return false;
    }
    if (std::find(pids.begin(), pids.end(), status.pid) == pids.end()) return false;
    return SendShowRequest(status.pid);
}
