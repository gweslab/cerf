#include "icon_sources.h"

#include "../cursor_icon.h"
#include "../qt_resource_paths.h"
#include "../resource_paths_text.h"

QString IconSources::AboutBand() const { return AssetImageUrl(QStringLiteral(CERF_ABOUT_BAND_ASSET)); }

QString IconSources::Logo() const { return AssetImageUrl(QStringLiteral(CERF_LOGO_ASSET)); }

QString IconSources::NewIcon() const { return SymbolIconUrl(QStringLiteral("add")); }

QString IconSources::SettingsIcon() const { return SymbolIconUrl(QStringLiteral("settings")); }

QString IconSources::LaunchSymbol() const { return QStringLiteral("play_arrow_fill"); }

QString IconSources::ResumeSymbol() const { return QStringLiteral("pause_fill"); }

QString IconSources::LaunchIcon() const { return SymbolIconUrl(LaunchSymbol()); }

QString IconSources::CursorSymbol() const { return QString::fromLatin1(kCursorIconName); }

QPointF IconSources::CursorHotspot() const { return QPointF(kCursorIconHotX, kCursorIconHotY); }

QString IconSources::Icon(const QString& name) const { return SymbolIconUrl(name); }

QString IconSources::Asset(const QString& stem) const { return AssetImageUrl(stem); }

QString IconSources::Tinted(const QString& name, const QColor& color) const { return TintedIconUrl(name, color); }
