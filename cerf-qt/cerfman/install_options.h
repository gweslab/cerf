#pragma once

#include "wait_for_pid.h"

#include <QString>
#include <QStringList>

#include <cstdint>
#include <optional>

enum class InstallStage { kInstall, kPostUpgrade };

struct InstallOptions {
    InstallStage            stage        = InstallStage::kInstall;
    std::optional<uint32_t> wait_pid;
    bool                    fresh        = false;
    bool                    desktop_icon = false;
    bool                    start_menu   = false;
    bool                    launch_after = true;

    QString     Heading() const;
    QString     FailedTitle() const;
    QStringList CarriedArguments() const;

    static InstallOptions Parse(int argc, char** argv);
};

inline constexpr char kInstallArg[]     = "--install";
inline constexpr char kUpgradeArg[]     = "--upgrade";
inline constexpr char kPostUpgradeArg[] = "--post-upgrade";
