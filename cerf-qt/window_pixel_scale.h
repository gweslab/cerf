#pragma once

#include <QObject>
#include <QPointF>
#include <QSize>

#include <atomic>

class QQuickWindow;

class WindowPixelScale : public QObject {
    Q_OBJECT

public:
    static WindowPixelScale* Of(QQuickWindow* window);

    QPointF Scale() const;

signals:
    void scaleChanged();

private:
    explicit WindowPixelScale(QQuickWindow* window);

    void  Measure();
    QSize ViewportSize() const;
    QSize GlViewportSize() const;

    QQuickWindow*       window_;
    std::atomic<double> x_{0.0};
    std::atomic<double> y_{0.0};
    std::atomic<double> ratio_{0.0};
};
