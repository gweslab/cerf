#include "qt_window_fit.h"

#include "../qt_device_pixels.h"

#include <QRect>
#include <QScreen>
#include <QWidget>

#include <algorithm>

QSize WindowChrome(const QWidget& window, const QWidget& content) {
    return window.frameGeometry().size() - content.size();
}

WindowFit FitAroundContent(const QWidget& window, const QWidget& content, uint32_t content_w, uint32_t content_h) {
    const qreal dpr     = window.devicePixelRatioF();
    const QSize frame   = window.frameGeometry().size() - window.geometry().size();
    const QSize chrome  = WindowChrome(window, content);
    const QRect work    = window.screen()->availableGeometry();
    const int   outer_w = std::min(LogicalExtentCovering(static_cast<int>(content_w), dpr) + chrome.width(), work.width());
    const int   outer_h =
        std::min(LogicalExtentCovering(static_cast<int>(content_h), dpr) + chrome.height(), work.height());
    return {QSize(outer_w - frame.width(), outer_h - frame.height()),
            QPoint(work.left() + (work.width() - outer_w) / 2, work.top() + (work.height() - outer_h) / 2)};
}
