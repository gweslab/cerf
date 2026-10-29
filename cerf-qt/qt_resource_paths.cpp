#include "qt_resource_paths.h"

#include "resource_paths_text.h"

#include <QFileInfo>

namespace {

QString QrcUrl(const QString& resource) { return QStringLiteral("qrc") + resource; }

QString ImageProviderUrl(const char* provider, const QString& id) {
    return QStringLiteral("image://%1/%2").arg(QLatin1String(provider), id);
}

}

QString AssetIconResource(const QString& stem) { return QStringLiteral(":/" CERF_ASSET_ICONS_DIR "/%1.svg").arg(stem); }

QString SymbolIconResource(const QString& stem) {
    return QStringLiteral(":" CERF_SYMBOL_ICONS_PREFIX "/%1.svg").arg(stem);
}

QString SymbolIconUrl(const QString& stem) { return QrcUrl(SymbolIconResource(stem)); }

QString AssetImageUrl(const QString& stem) { return ImageProviderUrl(CERF_ASSET_IMAGE_PROVIDER, stem); }

QString TintedIconUrl(const QString& stem, const QColor& color) {
    return ImageProviderUrl(CERF_SYMBOL_IMAGE_PROVIDER,
                            QStringLiteral("%1/%2").arg(stem, color.name(QColor::HexArgb).mid(1)));
}

QString TintedSymbolUrl(const QUrl& symbol_url, const QColor& color) {
    return TintedIconUrl(QFileInfo(symbol_url.path()).completeBaseName(), color);
}

TintedIconRequest ParseTintedIconRequest(const QString& id) {
    const qsizetype slash = id.indexOf(QLatin1Char('/'));
    return {id.left(slash), QColor(QLatin1Char('#') + id.mid(slash + 1))};
}

QString FontResource(const char* file_name) {
    return QStringLiteral(":/" CERF_FONTS_DIR "/") + QString::fromLatin1(file_name);
}

QString ContributorsResource() { return QStringLiteral(":/" CERF_CONTRIBUTORS_FILE); }

QString InstallResourceRoot() { return QStringLiteral(":" CERF_INSTALL_RESOURCE_PREFIX); }
