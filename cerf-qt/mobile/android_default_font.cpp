#include "android_default_font.h"

#include <cerfcore/core/log.h>

#include <QDir>
#include <QFileInfo>
#include <QFont>
#include <QFontDatabase>
#include <QGuiApplication>
#include <QRawFont>
#include <QStandardPaths>

namespace {

constexpr qreal kProbePixelSize = 12.0;

}

void RestoreDefaultFontCoverage() {
    const QFont font   = QGuiApplication::font();
    const QChar letter = u'a';
    if (QRawFont::fromFont(font).supportsCharacter(letter)) return;
    const QString family   = font.family();
    int           restored = 0;
    for (const QString& folder : QStandardPaths::standardLocations(QStandardPaths::FontsLocation)) {
        for (const QFileInfo& file : QDir(folder).entryInfoList(QDir::Files)) {
            const QString  path = file.absoluteFilePath();
            const QRawFont raw(path, kProbePixelSize);
            if (!raw.isValid() || raw.familyName() != family || !raw.supportsCharacter(letter)) continue;
            if (QFontDatabase::addApplicationFont(path) >= 0) ++restored;
        }
    }
    LOG(Manager, "AndroidDefaultFont: '%s' had no glyph for 'a', re-registered %d system font files\n",
        qUtf8Printable(family), restored);
}
