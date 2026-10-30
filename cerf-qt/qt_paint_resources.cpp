#include "qt_paint_resources.h"

#include "qt_device_pixels.h"
#include "qt_resource_paths.h"
#include "resource_paths_text.h"
#include "svg_document.h"
#include "tinted_symbol_icon.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>

#include <QFontDatabase>
#include <QFontInfo>
#include <QGuiApplication>
#include <QSize>
#include <QStringList>

REGISTER_SERVICE(QtPaintResources);

QString QtPaintResources::LoadFamily(const char* file_name) {
    const int id = QFontDatabase::addApplicationFont(FontResource(file_name));
    if (id < 0) return {};
    return QFontDatabase::applicationFontFamilies(id).front();
}

void QtPaintResources::OnReady() {
    const QString sans      = LoadFamily(CERF_FONT_SANS);
    const QString sans_bold = LoadFamily(CERF_FONT_SANS_BOLD);
    const QString mono      = LoadFamily(CERF_FONT_MONO_BOLD);

    ui_family_ = !sans.isEmpty() && !sans_bold.isEmpty()
                     ? sans
                     : QFontDatabase::systemFont(QFontDatabase::GeneralFont).family();
    mono_family_ = !mono.isEmpty() ? mono
                                   : QFontDatabase::systemFont(QFontDatabase::FixedFont).family();
    if (sans.isEmpty() || sans_bold.isEmpty())
        LOG(Caution, "QtPaintResources: IBM Plex Sans unavailable, falling back to '%s'\n",
            ui_family_.toUtf8().constData());
    if (mono.isEmpty())
        LOG(Caution, "QtPaintResources: IBM Plex Mono unavailable, falling back to '%s'\n",
            mono_family_.toUtf8().constData());
}

QFont QtPaintResources::Font(const cerffrontend::Font& font) const {
    if (font.face == cerffrontend::FontFace::kSystem) {
        QFont f = QGuiApplication::font();
        if (font.px != 0) f.setPixelSize(QFontInfo(f).pixelSize() + font.px);
        f.setBold(font.bold);
        return f;
    }
    const bool mono = font.face == cerffrontend::FontFace::kMono;
    QFont      f(mono ? mono_family_ : ui_family_);
    f.setPixelSize(font.px);
    f.setBold(font.bold);
    f.setStyleHint(mono ? QFont::Monospace : QFont::SansSerif);
    f.setFixedPitch(mono);
    return f;
}

const QImage& QtPaintResources::Icon(std::string_view stem, int px, qreal dpr) {
    return SvgImage(stem, px, px, dpr);
}

const QImage& QtPaintResources::SvgImage(std::string_view stem, int width, int height, qreal dpr) {
    auto key = std::make_tuple(std::string(stem), width, height, dpr);
    auto it  = svgs_.find(key);
    if (it != svgs_.end()) return it->second;

    const SvgDocument document(AssetIconResource(QString::fromUtf8(stem.data(), stem.size())));
    QImage image = document.Render(QSize(DeviceExtent(width, dpr), DeviceExtent(height, dpr)));
    image.setDevicePixelRatio(dpr);
    return svgs_.emplace(std::move(key), std::move(image)).first->second;
}

const QImage& QtPaintResources::Symbol(std::string_view stem, int px, qreal dpr, cerffrontend::Rgb color) {
    auto key = std::make_tuple(std::string(stem), px, dpr, color.r, color.g, color.b);
    auto it  = symbols_.find(key);
    if (it != symbols_.end()) return it->second;

    const int side  = DeviceExtent(px, dpr);
    QImage    image = TintedSymbolIcon(QString::fromUtf8(stem.data(), stem.size()), QSize(side, side),
                                       QColor(color.r, color.g, color.b));
    image.setDevicePixelRatio(dpr);
    return symbols_.emplace(std::move(key), std::move(image)).first->second;
}
