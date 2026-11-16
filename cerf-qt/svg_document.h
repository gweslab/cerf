#pragma once

#include <QByteArray>
#include <QImage>
#include <QRectF>
#include <QSize>
#include <QSizeF>
#include <QString>

struct resvg_render_tree;

class SvgDocument {
public:
    explicit SvgDocument(const QString& path);
    explicit SvgDocument(const QByteArray& data);
    ~SvgDocument();

    SvgDocument(const SvgDocument&)            = delete;
    SvgDocument& operator=(const SvgDocument&) = delete;

    bool   Loaded() const { return tree_ != nullptr; }
    QSizeF DefaultSize() const;
    QRectF ContentBounds() const;
    QImage Render(const QSize& size) const;
    QImage Render(const QSize& size, const QRectF& source) const;
    QImage RenderRequested(const QSize& requested_size, QSize* size) const;

private:
    resvg_render_tree* tree_ = nullptr;
};
