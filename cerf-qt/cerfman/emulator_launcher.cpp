#include "emulator_launcher.h"

#include "starting_devices.h"

#include <cerfcore/core/cerf_emulator.h>

QVariantMap EmulatorLauncher::Started(const QString& name) {
    emu_.Get<StartingDevices>().Mark(name);
    return QVariantMap{{QStringLiteral("status"), QStringLiteral("Started %1.").arg(name)}};
}
