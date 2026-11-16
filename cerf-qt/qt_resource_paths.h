#pragma once

#include <QColor>
#include <QRect>
#include <QSizeF>
#include <QString>
#include <QUrl>

struct TintedIconRequest {
    QString stem;
    QColor  color;
};

struct AssetImageRequest {
    QString stem;
    QSizeF  canvas_pixels;
    QRect   region;
};

QString AssetIconResource(const QString& stem);
QString SymbolIconResource(const QString& stem);
QString SymbolIconUrl(const QString& stem);
QString AssetImageUrl(const QString& stem);
QString AssetRegionImageUrl(const QString& stem, const QSizeF& canvas_pixels, const QRect& region);
AssetImageRequest ParseAssetImageRequest(const QString& id);
QString SvgFileImageUrl(const QString& path);
QString ParseSvgFileImageRequest(const QString& id);
QString TintedIconUrl(const QString& stem, const QColor& color);
QString TintedSymbolUrl(const QUrl& symbol_url, const QColor& color);
TintedIconRequest ParseTintedIconRequest(const QString& id);
QString FontResource(const char* file_name);
QString ContributorsResource();
QString InstallResourceRoot();
