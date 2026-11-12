#pragma once

#include <QPoint>
#include <QSize>

#include <cstdint>

class QQuickWindow;

struct WindowFit {
    QSize  client;
    QPoint position;
    bool   whole = true;
};

QSize     WindowChrome(const QQuickWindow& window);
WindowFit FitAroundContent(const QQuickWindow& window, uint32_t content_w, uint32_t content_h);
