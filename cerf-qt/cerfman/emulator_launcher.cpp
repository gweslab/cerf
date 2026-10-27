#include "emulator_launcher.h"

QVariantMap EmulatorLauncher::StartedReply(const QString& name) {
    return QVariantMap{{QStringLiteral("status"), QStringLiteral("Started %1.").arg(name)}};
}
