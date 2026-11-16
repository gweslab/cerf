#include "boot_logo_parts.h"

#include "qt_resource_paths.h"
#include "svg_document.h"

#include <QRectF>
#include <QSizeF>

namespace {

constexpr char kPartsDir[] = "boot_logo";
constexpr int  kRows       = 4;
constexpr int  kColumns    = 7;

QVariantMap Part(const QString& name) {
    const QString     stem = QLatin1String(kPartsDir) + QLatin1Char('/') + name;
    const SvgDocument document(AssetIconResource(stem));
    const QSizeF      canvas = document.DefaultSize();
    const QRectF      bounds = document.ContentBounds();
    return {
        {QStringLiteral("asset"), stem},
        {QStringLiteral("x"), bounds.x() / canvas.width()},
        {QStringLiteral("y"), bounds.y() / canvas.height()},
        {QStringLiteral("width"), bounds.width() / canvas.width()},
        {QStringLiteral("height"), bounds.height() / canvas.height()},
    };
}

}

BootLogoParts::BootLogoParts(QObject* parent)
    : QObject(parent), frame_(Part(QStringLiteral("frame"))), spinner_(Part(QStringLiteral("spinner"))) {
    for (int row = 0; row < kRows; ++row) {
        QVariantMap plate = Part(QStringLiteral("plate_%1").arg(row));
        plate.insert(QStringLiteral("row"), row);
        plates_.append(plate);
        for (int column = 0; column < kColumns; ++column) {
            QVariantMap box = Part(QStringLiteral("box_%1_%2").arg(row).arg(column));
            box.insert(QStringLiteral("row"), row);
            box.insert(QStringLiteral("column"), column);
            boxes_.append(box);
        }
    }
}

QString BootLogoParts::RegionSource(const QString& asset, const QSizeF& canvas_pixels, const QRectF& region) const {
    return AssetRegionImageUrl(asset, canvas_pixels, region.toRect());
}
