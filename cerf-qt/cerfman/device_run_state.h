#pragma once

#include <QString>

#include <cstdint>
#include <optional>
#include <vector>

struct RunningStatus {
    uint32_t pid  = 0;
    uint64_t hwnd = 0;
};

struct SavedStateInfo {
    QString file;
    bool    crash          = false;
    qint64  saved_at_msecs = 0;
    qint64  size           = 0;
};

enum class RunStateKind { kRunning, kSaved, kOff };

struct RunState {
    RunStateKind                  kind = RunStateKind::kOff;
    std::optional<SavedStateInfo> saved;
};

std::optional<RunningStatus>  ReadRunningStatus(const QString& device_path);
std::vector<SavedStateInfo>   ReadSavedStates(const QString& device_path);
std::optional<SavedStateInfo> ReadSavedState(const QString& device_path);
QString                       SavedStateTime(const SavedStateInfo& state);
QString                       SavedStateDetails(const SavedStateInfo& state);
QString                       SavedStateCaption(const SavedStateInfo& state);
RunState                      ReadRunState(const QString& device_path);
