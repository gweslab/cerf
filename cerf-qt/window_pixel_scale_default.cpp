#include "window_pixel_scale.h"

#include <QQuickWindow>
#include <QSGRendererInterface>

QSize WindowPixelScale::ViewportSize() const {
    if (window_->rendererInterface()->graphicsApi() != QSGRendererInterface::OpenGL) return QSize();
    return GlViewportSize();
}
