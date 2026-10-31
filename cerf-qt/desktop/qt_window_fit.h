#pragma once

#include <QPoint>
#include <QSize>

#include <cstdint>

class QWidget;

struct WindowFit {
    QSize  client;
    QPoint position;
    bool   whole = true;
};

QSize     WindowChrome(const QWidget& window, const QWidget& content);
WindowFit FitAroundContent(const QWidget& window, const QWidget& content, uint32_t content_w, uint32_t content_h);
