#pragma once

#include <memory>

class QWidget;

class QtRelativeMotionSink {
public:
    virtual void OnRelativeMotion(double dx, double dy) = 0;

protected:
    ~QtRelativeMotionSink() = default;
};

class QtPointerLock {
public:
    virtual ~QtPointerLock() = default;

    virtual bool Lock(QWidget& widget) = 0;
    virtual void Unlock()              = 0;
    virtual bool CanWarp()             = 0;
};

std::unique_ptr<QtPointerLock> MakeQtPointerLock(QtRelativeMotionSink& sink);
