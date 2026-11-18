#include "device_run_state.h"

#include "../device_status_files.h"
#include "byte_size_text.h"
#include "json_file.h"

#include <cerfcore/state/state_image_format.h>

#include <QDateTime>
#include <QDir>
#include <QFileInfo>

namespace {

constexpr double kRunningStaleSeconds = 7.0;

constexpr char kSavedCaption[]   = "Saved %1";
constexpr char kCrashedCaption[] = "Crashed %1";

std::optional<SavedStateInfo> ReadImage(const QString& device_path, const char* name, bool crash) {
    const QFileInfo info(QDir(device_path).filePath(QString::fromLatin1(name)));
    if (!info.isFile()) return std::nullopt;
    return SavedStateInfo{QString::fromLatin1(name), crash, info.lastModified().toMSecsSinceEpoch(), info.size()};
}

}

std::optional<RunningStatus> ReadRunningStatus(const QString& device_path) {
    QString                   error;
    const std::optional<Json> status = ReadJsonObject(
        QDir(device_path).filePath(QString::fromLatin1(cerffrontend::kRunningStatusFileName)), error);
    if (!status) return std::nullopt;
    const double now = double(QDateTime::currentMSecsSinceEpoch()) / 1000.0;
    if (now - status->at(cerffrontend::kRunningStatusHeartbeatKey).get<double>() >= kRunningStaleSeconds)
        return std::nullopt;
    return RunningStatus{status->at(cerffrontend::kRunningStatusPidKey).get<uint32_t>(),
                         status->at(cerffrontend::kRunningStatusWindowKey).get<uint64_t>()};
}

std::vector<SavedStateInfo> ReadSavedStates(const QString& device_path) {
    std::vector<SavedStateInfo> states;
    if (auto saved = ReadImage(device_path, cerfcore::kDefaultStateFile, false)) states.push_back(*saved);
    if (auto crash = ReadImage(device_path, cerfcore::kCrashStateFile, true)) states.push_back(*crash);
    return states;
}

std::optional<SavedStateInfo> ReadSavedState(const QString& device_path) {
    std::vector<SavedStateInfo> states = ReadSavedStates(device_path);
    if (states.empty()) return std::nullopt;
    return states.front();
}

QString SavedStateTime(const SavedStateInfo& state) {
    return QDateTime::fromMSecsSinceEpoch(state.saved_at_msecs).toString(QStringLiteral("dd.MM HH:mm"));
}

QString SavedStateDetails(const SavedStateInfo& state) {
    const QString size = FormatSize(state.size);
    return size.isEmpty() ? SavedStateTime(state) : QStringLiteral("%1 · %2").arg(SavedStateTime(state), size);
}

QString SavedStateCaption(const SavedStateInfo& state) {
    return QString::fromLatin1(state.crash ? kCrashedCaption : kSavedCaption).arg(SavedStateDetails(state));
}

RunState ReadRunState(const QString& device_path) {
    if (ReadRunningStatus(device_path)) return RunState{RunStateKind::kRunning, std::nullopt};
    if (std::optional<SavedStateInfo> saved = ReadSavedState(device_path))
        return RunState{RunStateKind::kSaved, saved};
    return RunState{};
}
