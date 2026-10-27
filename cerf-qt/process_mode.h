#pragma once

enum class ProcessMode { kManager, kEmulator, kInstallStage, kCrashReport };

inline constexpr char kCrashReportArg[] = "--crash-report=";

ProcessMode DetectProcessMode(int argc, char** argv);
