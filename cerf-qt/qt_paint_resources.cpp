#include "qt_paint_resources.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/fatal.h>
#include <cerfcore/core/log.h>

#include <QApplication>
#include <QFontDatabase>
#include <QFontInfo>
#include <QPainter>
#include <QRectF>
#include <QStringList>
#include <QSvgRenderer>

#include <cmath>

REGISTER_SERVICE(QtPaintResources);

QString QtPaintResources::LoadFamily(const char* resource) {
    const int id = QFontDatabase::addApplicationFont(QString::fromLatin1(resource));
    if (id < 0) return {};
    const QStringList families = QFontDatabase::applicationFontFamilies(id);
    return families.isEmpty() ? QString() : families.front();
}

void QtPaintResources::OnReady() {
    const QString sans      = LoadFamily(":/fonts/IBMPlexSans-Regular.ttf");
    const QString sans_bold = LoadFamily(":/fonts/IBMPlexSans-Bold.ttf");
    const QString mono      = LoadFamily(":/fonts/IBMPlexMono-Bold.ttf");

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
        QFont f = QApplication::font();
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

const QImage& QtPaintResources::Logo() {
    if (logo_.isNull()) {
        logo_ = QImage(QStringLiteral(":/cerf_1024.png"));
        if (logo_.isNull())
            emu_.Get<cerfcore::Fatal>().Die("QtPaintResources: the CERF logo resource is absent");
    }
    return logo_;
}

const QImage& QtPaintResources::Icon(std::string_view stem, int px, qreal dpr) {
    return SvgImage(stem, px, px, dpr);
}

const QImage& QtPaintResources::SvgImage(std::string_view stem, int width, int height, qreal dpr) {
    auto key = std::make_tuple(std::string(stem), width, height, dpr);
    auto it  = svgs_.find(key);
    if (it != svgs_.end()) return it->second;

    const QString path =
        QStringLiteral(":/icons_sources/%1.svg").arg(QString::fromUtf8(stem.data(), stem.size()));
    QSvgRenderer renderer(path);
    const int    device_w = static_cast<int>(std::lround(width * dpr));
    const int    device_h = static_cast<int>(std::lround(height * dpr));
    if (!renderer.isValid() || device_w <= 0 || device_h <= 0)
        emu_.Get<cerfcore::Fatal>().Die("QtPaintResources: SVG '%s' at %dx%d not renderable",
                                        std::get<0>(key).c_str(), device_w, device_h);
    QImage image(device_w, device_h, QImage::Format_ARGB32_Premultiplied);
    image.fill(Qt::transparent);
    QPainter painter(&image);
    renderer.render(&painter, QRectF(0, 0, device_w, device_h));
    painter.end();
    image.setDevicePixelRatio(dpr);
    return svgs_.emplace(std::move(key), std::move(image)).first->second;
}
