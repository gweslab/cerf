#pragma once

#include <QPointF>

#include <memory>

class QWindow;

class QtRelativeMotionSink {
public:
    virtual void    OnRelativeMotion(double dx, double dy) = 0;
    virtual QPointF RestInWindow() const                   = 0;

protected:
    ~QtRelativeMotionSink() = default;
};

class QtPointerLock {
public:
    virtual ~QtPointerLock() = default;

    virtual bool Lock(QWindow& window) = 0;
    virtual void Unlock()              = 0;
    virtual bool CanWarp()             = 0;
};

std::unique_ptr<QtPointerLock> MakeQtPointerLock(QtRelativeMotionSink& sink);
