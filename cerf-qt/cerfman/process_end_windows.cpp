#include "process_end.h"

#include <cerfcore/platform/host_error.h>

#define NOMINMAX
#include <windows.h>

namespace {

QString EndFailure(uint32_t pid) {
    return QStringLiteral("cannot end process %1 (%2)")
        .arg(pid)
        .arg(QString::fromStdString(cerfcore::host_platform::ErrorText(cerfcore::host_platform::LastErrorCode())));
}

}

bool EndProcess(uint32_t pid, QString& error) {
    HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, DWORD(pid));
    if (process == nullptr) {
        error = EndFailure(pid);
        return false;
    }
    const BOOL ended = TerminateProcess(process, 1);
    if (!ended) error = EndFailure(pid);
    CloseHandle(process);
    return ended != FALSE;
}
