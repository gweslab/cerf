#define NOMINMAX

#include "window_pixel_scale.h"

#include <QQuickWindow>
#include <QSGRendererInterface>

#include <d3d11.h>

#include <cmath>

QSize WindowPixelScale::ViewportSize() const {
    QSGRendererInterface* renderer = window_->rendererInterface();
    switch (renderer->graphicsApi()) {
        case QSGRendererInterface::Direct3D11: {
            auto* context = static_cast<ID3D11DeviceContext*>(
                renderer->getResource(window_, QSGRendererInterface::DeviceContextResource));
            UINT           count = 1;
            D3D11_VIEWPORT viewport{};
            context->RSGetViewports(&count, &viewport);
            if (count == 0) return QSize();
            return QSize(static_cast<int>(std::lround(viewport.Width)), static_cast<int>(std::lround(viewport.Height)));
        }
        case QSGRendererInterface::OpenGL: return GlViewportSize();
        default:                           return QSize();
    }
}
