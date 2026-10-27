#pragma once

#include <QColor>
#include <QString>
#include <QUrl>

struct TintedIconRequest {
    QString stem;
    QColor  color;
};

QString AssetIconResource(const QString& stem);
QString SymbolIconResource(const QString& stem);
QString SymbolIconUrl(const QString& stem);
QString AssetImageUrl(const QString& stem);
QString TintedIconUrl(const QString& stem, const QColor& color);
QString TintedSymbolUrl(const QUrl& symbol_url, const QColor& color);
TintedIconRequest ParseTintedIconRequest(const QString& id);
QString FontResource(const char* file_name);
QString ContributorsResource();
QString BadgeStem(const QString& key);
QString BadgeUrl(const QString& key);
QString InstallResourceRoot();
