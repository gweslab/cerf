#include "install_options.h"

#include <cerfcore/core/product_name.h>

#include <cstring>

namespace {

constexpr char kDesktopIconArg[] = "--create-desktop-icon";
constexpr char kStartMenuArg[]   = "--create-start-menu-entry";
constexpr char kNoLaunchArg[]    = "--do-not-launch-after-install";

}

QString InstallOptions::Heading() const {
    return (fresh ? QStringLiteral("Installing %1…") : QStringLiteral("Upgrading %1…"))
        .arg(QString::fromUtf8(CERF_PRODUCT_NAME));
}

QString InstallOptions::FailedTitle() const {
    return fresh ? QStringLiteral("Install failed") : QStringLiteral("Upgrade failed");
}

QStringList InstallOptions::CarriedArguments() const {
    QStringList args;
    if (fresh) args.append(QString::fromLatin1(kInstallArg));
    if (desktop_icon) args.append(QString::fromLatin1(kDesktopIconArg));
    if (start_menu) args.append(QString::fromLatin1(kStartMenuArg));
    if (!launch_after) args.append(QString::fromLatin1(kNoLaunchArg));
    return args;
}

InstallOptions InstallOptions::Parse(int argc, char** argv) {
    InstallOptions options;
    bool           post_upgrade = false;
    for (int i = 1; i < argc; ++i) {
        const char*             arg = argv[i];
        std::optional<uint32_t> pid;
        if (ParseWaitForPidArg(arg, pid)) {
            if (!options.wait_pid) options.wait_pid = pid;
        } else if (std::strcmp(arg, kPostUpgradeArg) == 0) {
            post_upgrade = true;
        } else if (std::strcmp(arg, kInstallArg) == 0) {
            options.fresh = true;
        } else if (std::strcmp(arg, kDesktopIconArg) == 0) {
            options.desktop_icon = true;
        } else if (std::strcmp(arg, kStartMenuArg) == 0) {
            options.start_menu = true;
        } else if (std::strcmp(arg, kNoLaunchArg) == 0) {
            options.launch_after = false;
        }
    }
    options.stage = post_upgrade ? InstallStage::kPostUpgrade : InstallStage::kInstall;
    return options;
}
