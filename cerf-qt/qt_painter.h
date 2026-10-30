#pragma once

#include "painter.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QString>
#include <QStringList>

class QPainter;

class QtPainter final : public cerffrontend::Painter {
public:
    QtPainter(cerfcore::CerfEmulator& emu, QPainter& painter) : emu_(emu), p_(painter) {}

    void FillRect(const cerffrontend::Rect& r, cerffrontend::Rgb color) override;
    void BlendRect(const cerffrontend::Rect& r, cerffrontend::Rgb color, uint8_t alpha) override;
    void Rectangle(const cerffrontend::Rect& r, cerffrontend::Rgb pen, int pen_width,
                   const cerffrontend::Rgb* fill) override;
    void RoundRect(const cerffrontend::Rect& r, int corner_w, int corner_h, cerffrontend::Rgb pen,
                   cerffrontend::Rgb fill) override;
    void Ellipse(const cerffrontend::Rect& r, cerffrontend::Rgb pen, cerffrontend::Rgb fill) override;
    void Polyline(const cerffrontend::Point* points, int count, cerffrontend::Rgb pen,
                  int pen_width) override;

    void FillCircleAA(int cx, int cy, int radius, cerffrontend::Rgb fill,
                      cerffrontend::Rgb rim) override;
    void FillPolygonAA(const cerffrontend::Point* points, int count, cerffrontend::Rgb fill,
                       cerffrontend::Rgb rim) override;
    void FillRoundRectAA(const cerffrontend::Rect& r, int radius, cerffrontend::Rgb fill,
                         cerffrontend::Rgb rim) override;
    void FillRoundRectAlphaAA(const cerffrontend::Rect& r, int radius, cerffrontend::Rgb fill,
                              uint8_t alpha) override;
    void FillGradient(const cerffrontend::Rect& r, cerffrontend::Point from, cerffrontend::Point to,
                      const cerffrontend::GradientStop* stops, int count) override;

    void DrawTextBox(const cerffrontend::Rect& r, std::string_view utf8,
                     const cerffrontend::Font& font, cerffrontend::Rgb color,
                     uint32_t flags) override;
    void DrawTextAt(int x, int y, std::string_view utf8, const cerffrontend::Font& font,
                    cerffrontend::Rgb color) override;
    int  TextHeight(std::string_view utf8, const cerffrontend::Font& font, int width,
                    uint32_t flags) override;
    int  TextWidth(std::string_view utf8, const cerffrontend::Font& font) override;
    cerffrontend::FontMetrics Metrics(const cerffrontend::Font& font) override;

    void DrawIcon(const cerffrontend::Rect& box, std::string_view stem, int px) override;
    void DrawSymbol(const cerffrontend::Rect& box, std::string_view stem, int px,
                    cerffrontend::Rgb color) override;
    void DrawImage(const cerffrontend::Rect& dst, cerffrontend::PainterImage image,
                   float opacity) override;

private:
    QStringList Lines(const QString& text, int width, uint32_t flags);

    cerfcore::CerfEmulator& emu_;
    QPainter&               p_;
};
