#include "window_pixel_scale.h"

#include <QOpenGLContext>
#include <QOpenGLFunctions>
#include <QQuickWindow>

WindowPixelScale::WindowPixelScale(QQuickWindow* window) : QObject(window), window_(window) {
    connect(window, &QQuickWindow::afterRenderPassRecording, this, &WindowPixelScale::Measure, Qt::DirectConnection);
}

WindowPixelScale* WindowPixelScale::Of(QQuickWindow* window) {
    auto* found = window->findChild<WindowPixelScale*>(QString(), Qt::FindDirectChildrenOnly);
    return found != nullptr ? found : new WindowPixelScale(window);
}

QPointF WindowPixelScale::Scale() const {
    const qreal dpr = window_->effectiveDevicePixelRatio();
    if (ratio_.load(std::memory_order_acquire) != dpr) return QPointF(dpr, dpr);
    return QPointF(x_.load(std::memory_order_relaxed), y_.load(std::memory_order_relaxed));
}

void WindowPixelScale::Measure() {
    window_->beginExternalCommands();
    const QSize viewport = ViewportSize();
    window_->endExternalCommands();
    if (viewport.isEmpty()) return;
    const qreal dpr     = window_->effectiveDevicePixelRatio();
    const QSize logical = viewport / dpr;
    if (logical.isEmpty()) return;
    const double x = static_cast<double>(viewport.width()) / logical.width();
    const double y = static_cast<double>(viewport.height()) / logical.height();
    if (x == x_.load(std::memory_order_relaxed) && y == y_.load(std::memory_order_relaxed) &&
        dpr == ratio_.load(std::memory_order_relaxed))
        return;
    x_.store(x, std::memory_order_relaxed);
    y_.store(y, std::memory_order_relaxed);
    ratio_.store(dpr, std::memory_order_release);
    QMetaObject::invokeMethod(this, &WindowPixelScale::scaleChanged, Qt::QueuedConnection);
}

QSize WindowPixelScale::GlViewportSize() const {
    GLint viewport[4] = {};
    QOpenGLContext::currentContext()->functions()->glGetIntegerv(GL_VIEWPORT, viewport);
    return QSize(viewport[2], viewport[3]);
}
