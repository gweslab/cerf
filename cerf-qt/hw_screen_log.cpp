#include "hw_screen_log.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/hw_screen.h>

#include <QString>

#include <string>
#include <string_view>
#include <vector>

namespace cerffrontend {

REGISTER_SERVICE(HwScreenLog);

namespace {

const QList<QByteArray> kRoles = {"text", "tone"};

bool ContainsCI(std::string_view hay, std::string_view needle) {
    if (needle.empty() || needle.size() > hay.size()) return false;
    for (size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        size_t j = 0;
        for (; j < needle.size(); ++j) {
            char a = hay[i + j];
            if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
            if (a != needle[j]) break;
        }
        if (j == needle.size()) return true;
    }
    return false;
}

const char* LineTone(std::string_view line) {
    if (ContainsCI(line, "abort") || ContainsCI(line, "fail") || ContainsCI(line, "error") ||
        ContainsCI(line, "exception"))
        return "error";
    if (ContainsCI(line, "warning")) return "warning";
    return "text";
}

}

void HwScreenLog::OnReady() {
    emu_.Get<cerfcore::HwScreen>().Subscribe(
        [this](const std::string&) { dirty_.store(true, std::memory_order_release); });
}

QList<QByteArray> HwScreenLog::Roles() { return kRoles; }

bool HwScreenLog::Rebuild() {
    if (!dirty_.exchange(false, std::memory_order_acq_rel)) return false;
    std::vector<std::string> snapshot;
    emu_.Get<cerfcore::HwScreen>().Snapshot(snapshot);
    rows_.clear();
    for (const std::string& line : snapshot)
        rows_.append({{QStringLiteral("text"), QString::fromStdString(line)},
                      {QStringLiteral("tone"), QString::fromLatin1(LineTone(line))}});
    return true;
}

}
