#include "device_run_state.h"

#include "../device_status_files.h"
#include "json_file.h"

#include <cerfcore/state/state_image_format.h>

#include <QDateTime>
#include <QDir>
#include <QFileInfo>

namespace {

constexpr double kRunningStaleSeconds = 7.0;

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

std::optional<SavedStateInfo> ReadSavedState(const QString& device_path) {
    const QFileInfo info(QDir(device_path).filePath(QString::fromLatin1(cerfcore::kDefaultStateFile)));
    if (!info.isFile()) return std::nullopt;
    return SavedStateInfo{info.lastModified().toMSecsSinceEpoch(), info.size()};
}

RunState ReadRunState(const QString& device_path) {
    if (ReadRunningStatus(device_path)) return RunState{RunStateKind::kRunning, std::nullopt};
    if (std::optional<SavedStateInfo> saved = ReadSavedState(device_path))
        return RunState{RunStateKind::kSaved, saved};
    return RunState{};
}
