#pragma once

#include <QImage>
#include <QRectF>
#include <QSize>
#include <QSizeF>
#include <QString>

struct resvg_render_tree;

class SvgDocument {
public:
    explicit SvgDocument(const QString& path);
    ~SvgDocument();

    SvgDocument(const SvgDocument&)            = delete;
    SvgDocument& operator=(const SvgDocument&) = delete;

    QSizeF DefaultSize() const;
    QRectF ContentBounds() const;
    QImage Render(const QSize& size) const;
    QImage Render(const QSize& size, const QRectF& source) const;

private:
    resvg_render_tree* tree_ = nullptr;
};
