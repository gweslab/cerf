#pragma once

#include <QImage>
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
    QImage Render(const QSize& size) const;

private:
    resvg_render_tree* tree_ = nullptr;
};
