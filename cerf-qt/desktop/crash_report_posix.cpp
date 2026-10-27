#include "crash_report.h"

#include "../process_mode.h"
#include "../product_links.h"

#include <cerfcore/core/product_name.h>
#include <cerfcore/core/text_append.h>
#include <cerfcore/platform/host_process.h>

#include <unistd.h>

#include <climits>
#include <cstring>
#include <string>

namespace {

using cerfcore::AppendText;

char g_executable[PATH_MAX];

void WriteError(const char* text) {
    [[maybe_unused]] const ssize_t written = ::write(STDERR_FILENO, text, std::strlen(text));
}

}

void QtCrashReport::Prepare() {
    const std::string path = cerfcore::host_platform::ExecutablePath();
    AppendText(g_executable, path.c_str());
}

void QtCrashReport::Present(const char* log_file) {
    char argument[sizeof(kCrashReportArg) + PATH_MAX] = {};
    AppendText(argument, kCrashReportArg);
    AppendText(argument, log_file);
    char* const arguments[] = {g_executable, argument, nullptr};
    ::execv(g_executable, arguments);
    WriteError(cerfcore::kProductName);
    WriteError(" stopped on an unexpected error. Log: ");
    WriteError(log_file);
    WriteError("\n\nIf you think this is a bug - open ");
    WriteError(cerffrontend::kFeedbackUrl.text);
    WriteError(" and file a bug report");
    WriteError("\n");
}
