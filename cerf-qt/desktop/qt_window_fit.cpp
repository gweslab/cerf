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
    const int   need_w  = LogicalExtentCovering(static_cast<int>(content_w), dpr) + chrome.width();
    const int   need_h  = LogicalExtentCovering(static_cast<int>(content_h), dpr) + chrome.height();
    const int   outer_w = std::min(need_w, work.width());
    const int   outer_h = std::min(need_h, work.height());
    return {QSize(outer_w - frame.width(), outer_h - frame.height()),
            QPoint(work.left() + (work.width() - outer_w) / 2, work.top() + (work.height() - outer_h) / 2),
            need_w <= work.width() && need_h <= work.height()};
}
