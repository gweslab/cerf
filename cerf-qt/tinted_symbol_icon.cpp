#include "tinted_symbol_icon.h"

#include "qt_resource_paths.h"
#include "svg_document.h"

#include <QPainter>

QImage TintedSymbolIcon(const QString& stem, const QSize& size, const QColor& color) {
    const SvgDocument document(SymbolIconResource(stem));
    QImage            image = document.Render(size.isValid() ? size : document.DefaultSize().toSize());
    QPainter          painter(&image);
    painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
    painter.fillRect(image.rect(), color);
    painter.end();
    return image;
}
