#include "qt_painter.h"

#include "qt_paint_resources.h"

#include <QFontMetrics>
#include <QPainter>
#include <QPainterPath>
#include <QPolygon>
#include <QPolygonF>
#include <QTextLayout>
#include <QTextOption>

namespace {

namespace text = cerffrontend::text;

QColor Color(cerffrontend::Rgb c, int alpha = 255) { return QColor(c.r, c.g, c.b, alpha); }

QRect FillArea(const cerffrontend::Rect& r) { return QRect(r.left, r.top, r.Width(), r.Height()); }

QRect OutlineArea(const cerffrontend::Rect& r) {
    return QRect(r.left, r.top, r.Width() - 1, r.Height() - 1);
}

QPen SolidPen(cerffrontend::Rgb c, int width) {
    QPen pen(Color(c));
    pen.setWidth(width);
    pen.setJoinStyle(Qt::MiterJoin);
    return pen;
}

QPainterPath RoundRectPath(qreal x, qreal y, qreal w, qreal h, qreal radius) {
    QPainterPath path;
    if (radius <= 0.0) {
        path.addRect(x, y, w, h);
        return path;
    }
    path.addRoundedRect(x, y, w, h, radius, radius);
    return path;
}

}

void QtPainter::FillRect(const cerffrontend::Rect& r, cerffrontend::Rgb color) {
    p_.fillRect(FillArea(r), Color(color));
}

void QtPainter::BlendRect(const cerffrontend::Rect& r, cerffrontend::Rgb color, uint8_t alpha) {
    p_.save();
    p_.setCompositionMode(QPainter::CompositionMode_SourceOver);
    p_.fillRect(FillArea(r), Color(color, alpha));
    p_.restore();
}

void QtPainter::Rectangle(const cerffrontend::Rect& r, cerffrontend::Rgb pen, int pen_width,
                          const cerffrontend::Rgb* fill) {
    p_.save();
    p_.setRenderHint(QPainter::Antialiasing, false);
    p_.setPen(SolidPen(pen, pen_width));
    p_.setBrush(fill ? QBrush(Color(*fill)) : Qt::NoBrush);
    p_.drawRect(OutlineArea(r));
    p_.restore();
}

void QtPainter::RoundRect(const cerffrontend::Rect& r, int corner_w, int corner_h,
                          cerffrontend::Rgb pen, cerffrontend::Rgb fill) {
    p_.save();
    p_.setRenderHint(QPainter::Antialiasing, false);
    p_.setPen(SolidPen(pen, 1));
    p_.setBrush(Color(fill));
    p_.drawRoundedRect(OutlineArea(r), corner_w / 2.0, corner_h / 2.0, Qt::AbsoluteSize);
    p_.restore();
}

void QtPainter::Ellipse(const cerffrontend::Rect& r, cerffrontend::Rgb pen, cerffrontend::Rgb fill) {
    p_.save();
    p_.setRenderHint(QPainter::Antialiasing, false);
    p_.setPen(SolidPen(pen, 1));
    p_.setBrush(Color(fill));
    p_.drawEllipse(OutlineArea(r));
    p_.restore();
}

void QtPainter::Polyline(const cerffrontend::Point* points, int count, cerffrontend::Rgb pen,
                         int pen_width) {
    if (count < 2) return;
    QPolygon poly;
    for (int i = 0; i < count; ++i) poly << QPoint(points[i].x, points[i].y);
    p_.save();
    p_.setRenderHint(QPainter::Antialiasing, false);
    p_.setPen(SolidPen(pen, pen_width));
    p_.drawPolyline(poly);
    p_.restore();
}

void QtPainter::FillCircleAA(int cx, int cy, int radius, cerffrontend::Rgb fill,
                             cerffrontend::Rgb rim) {
    const qreal x = static_cast<qreal>(cx - radius) + 0.5;
    const qreal y = static_cast<qreal>(cy - radius) + 0.5;
    const qreal d = static_cast<qreal>(2 * radius) - 1.0;
    p_.save();
    p_.setRenderHint(QPainter::Antialiasing, true);
    p_.setPen(Qt::NoPen);
    p_.setBrush(Color(fill));
    p_.drawEllipse(QRectF(x, y, d, d));
    p_.setPen(QPen(Color(rim), 1.0));
    p_.setBrush(Qt::NoBrush);
    p_.drawEllipse(QRectF(x, y, d, d));
    p_.restore();
}

void QtPainter::FillPolygonAA(const cerffrontend::Point* points, int count, cerffrontend::Rgb fill,
                              cerffrontend::Rgb rim) {
    QPolygonF poly;
    for (int i = 0; i < count; ++i) poly << QPointF(points[i].x, points[i].y);
    p_.save();
    p_.setRenderHint(QPainter::Antialiasing, true);
    p_.setPen(Qt::NoPen);
    p_.setBrush(Color(fill));
    p_.drawPolygon(poly);
    p_.setPen(QPen(Color(rim), 1.0));
    p_.setBrush(Qt::NoBrush);
    p_.drawPolygon(poly);
    p_.restore();
}

void QtPainter::FillRoundRectAA(const cerffrontend::Rect& r, int radius, cerffrontend::Rgb fill,
                                cerffrontend::Rgb rim) {
    const QPainterPath path = RoundRectPath(r.left + 0.5, r.top + 0.5, r.Width() - 1.0,
                                            r.Height() - 1.0, radius);
    p_.save();
    p_.setRenderHint(QPainter::Antialiasing, true);
    p_.fillPath(path, Color(fill));
    p_.strokePath(path, QPen(Color(rim), 1.0));
    p_.restore();
}

void QtPainter::FillRoundRectAlphaAA(const cerffrontend::Rect& r, int radius, cerffrontend::Rgb fill,
                                     uint8_t alpha) {
    const QPainterPath path = RoundRectPath(r.left, r.top, r.Width(), r.Height(), radius);
    p_.save();
    p_.setRenderHint(QPainter::Antialiasing, true);
    p_.fillPath(path, Color(fill, alpha));
    p_.restore();
}

QStringList QtPainter::Lines(const QString& text, int width, uint32_t flags) {
    if (flags & text::kSingleLine) return {text};
    QStringList out;
    QString     body = text;
    body.remove(QLatin1Char('\r'));
    for (const QString& para : body.split(QLatin1Char('\n'))) {
        if (!(flags & text::kWordBreak) || para.isEmpty()) {
            out << para;
            continue;
        }
        QTextLayout layout(para, p_.font());
        QTextOption option;
        option.setWrapMode(QTextOption::WordWrap);
        layout.setTextOption(option);
        layout.beginLayout();
        for (;;) {
            QTextLine line = layout.createLine();
            if (!line.isValid()) break;
            line.setLineWidth(width);
            out << para.mid(line.textStart(), line.textLength());
        }
        layout.endLayout();
    }
    return out;
}

void QtPainter::DrawTextBox(const cerffrontend::Rect& r, std::string_view utf8,
                            const cerffrontend::Font& font, cerffrontend::Rgb color,
                            uint32_t flags) {
    p_.save();
    p_.setFont(emu_.Get<QtPaintResources>().Font(font));
    const QFontMetrics fm(p_.font());
    const int          lh    = fm.height();
    QStringList        lines = Lines(QString::fromUtf8(utf8.data(), static_cast<int>(utf8.size())),
                                     r.Width(), flags);
    if ((flags & text::kEndEllipsis) && (flags & text::kSingleLine))
        lines[0] = fm.elidedText(lines[0], Qt::ElideRight, r.Width());

    int y = r.top;
    if ((flags & text::kVCenter) && (flags & text::kSingleLine)) y = r.top + (r.Height() - lh) / 2;
    if ((flags & text::kBottom) && (flags & text::kSingleLine)) y = r.bottom - lh;

    p_.setClipRect(FillArea(r), Qt::IntersectClip);
    p_.setPen(Color(color));
    for (const QString& line : lines) {
        if ((flags & text::kEditControl) && y + lh > r.bottom) break;
        int x = r.left;
        if (flags & text::kCenter) {
            QString shown = line;
            while (shown.endsWith(QLatin1Char(' '))) shown.chop(1);
            x = r.left + (r.Width() - fm.horizontalAdvance(shown)) / 2;
        }
        p_.drawText(QPoint(x, y + fm.ascent()), line);
        y += lh;
    }
    p_.restore();
}

void QtPainter::DrawTextAt(int x, int y, std::string_view utf8, const cerffrontend::Font& font,
                           cerffrontend::Rgb color) {
    p_.save();
    p_.setFont(emu_.Get<QtPaintResources>().Font(font));
    p_.setPen(Color(color));
    p_.drawText(QPoint(x, y + QFontMetrics(p_.font()).ascent()),
                QString::fromUtf8(utf8.data(), static_cast<int>(utf8.size())));
    p_.restore();
}

int QtPainter::TextHeight(std::string_view utf8, const cerffrontend::Font& font, int width,
                          uint32_t flags) {
    p_.save();
    p_.setFont(emu_.Get<QtPaintResources>().Font(font));
    const QFontMetrics fm(p_.font());
    const int          lines = static_cast<int>(
        Lines(QString::fromUtf8(utf8.data(), static_cast<int>(utf8.size())), width, flags).size());
    p_.restore();
    return lines * fm.height();
}

cerffrontend::FontMetrics QtPainter::Metrics(const cerffrontend::Font& font) {
    const QFontMetrics fm(emu_.Get<QtPaintResources>().Font(font));
    return cerffrontend::FontMetrics{fm.height(), fm.averageCharWidth()};
}

void QtPainter::DrawIcon(const cerffrontend::Rect& box, std::string_view stem, int px) {
    const QImage& icon = emu_.Get<QtPaintResources>().Icon(stem, px, p_.device()->devicePixelRatioF());
    p_.drawImage(QPoint(box.left + (box.Width() - px) / 2, box.top + (box.Height() - px) / 2), icon);
}

void QtPainter::DrawImage(const cerffrontend::Rect& dst, cerffrontend::PainterImage image,
                          float opacity) {
    if (dst.Width() <= 0 || dst.Height() <= 0) return;
    switch (image) {
        case cerffrontend::PainterImage::kCerfLogo:
            p_.save();
            p_.setRenderHint(QPainter::SmoothPixmapTransform, true);
            p_.setOpacity(opacity);
            p_.drawImage(FillArea(dst), emu_.Get<QtPaintResources>().Logo());
            p_.restore();
            return;
    }
}

bool QtPainter::ImageSize(cerffrontend::PainterImage image, int& w, int& h) {
    switch (image) {
        case cerffrontend::PainterImage::kCerfLogo: {
            const QImage& logo = emu_.Get<QtPaintResources>().Logo();
            w                  = logo.width();
            h                  = logo.height();
            return true;
        }
    }
    return false;
}
