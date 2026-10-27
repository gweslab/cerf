#pragma once

#include <QString>

#include <cstdint>
#include <optional>

struct RunningStatus {
    uint32_t pid  = 0;
    uint64_t hwnd = 0;
};

struct SavedStateInfo {
    qint64 saved_at_msecs = 0;
    qint64 size           = 0;
};

enum class RunStateKind { kRunning, kSaved, kOff };

struct RunState {
    RunStateKind                  kind = RunStateKind::kOff;
    std::optional<SavedStateInfo> saved;
};

std::optional<RunningStatus>  ReadRunningStatus(const QString& device_path);
std::optional<SavedStateInfo> ReadSavedState(const QString& device_path);
RunState                      ReadRunState(const QString& device_path);
