#include "legacy_windows.h"

#include <QOperatingSystemVersion>

bool LegacyWindows::Active() {
    return QOperatingSystemVersion::currentType() == QOperatingSystemVersion::Windows &&
           QOperatingSystemVersion::current() < QOperatingSystemVersion::Windows8;
}
