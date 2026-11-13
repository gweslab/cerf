#include "qt_pointer_lock.h"

#include <cerfcore/core/log.h>

#include <QWindow>

#include <cmath>
#include <memory>

#import <AppKit/AppKit.h>
#import <CoreGraphics/CoreGraphics.h>

namespace {

constexpr NSEventMask kMotionMask = NSEventMaskMouseMoved | NSEventMaskLeftMouseDragged |
                                    NSEventMaskRightMouseDragged | NSEventMaskOtherMouseDragged;

class DetachedPointerLock final : public QtPointerLock {
public:
    explicit DetachedPointerLock(QtRelativeMotionSink& sink) : sink_(sink) {}
    ~DetachedPointerLock() override;

    bool Lock(QWindow& window) override;
    void Unlock() override;
    bool CanWarp() override { return true; }

private:
    void OnMotion(NSEvent* event);
    void Recenter();

    QtRelativeMotionSink& sink_;
    QWindow*              window_  = nullptr;
    id                    monitor_ = nil;
    std::shared_ptr<bool> live_;
    double                warp_dx_ = 0.0;
    double                warp_dy_ = 0.0;
};

DetachedPointerLock::~DetachedPointerLock() {
    if (monitor_ != nil) Unlock();
}

bool DetachedPointerLock::Lock(QWindow& window) {
    if (CGAssociateMouseAndMouseCursorPosition(false) != kCGErrorSuccess) {
        LOG(Caution, "PointerLock: CGAssociateMouseAndMouseCursorPosition failed\n");
        return false;
    }
    window_  = &window;
    warp_dx_ = 0.0;
    warp_dy_ = 0.0;
    Recenter();
    DetachedPointerLock*        self = this;
    const std::shared_ptr<bool> live = std::make_shared<bool>(true);
    live_                            = live;
    monitor_ = [NSEvent addLocalMonitorForEventsMatchingMask:kMotionMask
                                                     handler:^NSEvent*(NSEvent* event) {
                                                         if (*live) self->OnMotion(event);
                                                         return event;
                                                     }];
    return true;
}

void DetachedPointerLock::Unlock() {
    *live_ = false;
    live_.reset();
    id monitor = monitor_;
    monitor_   = nil;
    window_    = nullptr;
    dispatch_async(dispatch_get_main_queue(), ^{
        [NSEvent removeMonitor:monitor];
    });
    if (CGAssociateMouseAndMouseCursorPosition(true) != kCGErrorSuccess)
        LOG(Caution, "PointerLock: CGAssociateMouseAndMouseCursorPosition failed\n");
}

void DetachedPointerLock::OnMotion(NSEvent* event) {
    const double dx = event.deltaX - warp_dx_;
    const double dy = event.deltaY - warp_dy_;
    warp_dx_        = 0.0;
    warp_dy_        = 0.0;
    Recenter();
    if (dx != 0.0 || dy != 0.0) sink_.OnRelativeMotion(dx, dy);
}

void DetachedPointerLock::Recenter() {
    const QPointF rest    = window_->mapToGlobal(sink_.RestInWindow());
    const QPointF want(std::round(rest.x()), std::round(rest.y()));
    const NSPoint mouse   = [NSEvent mouseLocation];
    const double  primary = NSScreen.screens.firstObject.frame.size.height;
    const double  now_x   = mouse.x;
    const double  now_y   = primary - mouse.y;
    if (std::lround(now_x) == std::lround(want.x()) && std::lround(now_y) == std::lround(want.y())) return;
    if (CGWarpMouseCursorPosition(CGPointMake(want.x(), want.y())) != kCGErrorSuccess) {
        LOG(Caution, "PointerLock: CGWarpMouseCursorPosition failed\n");
        return;
    }
    warp_dx_ += want.x() - now_x;
    warp_dy_ += want.y() - now_y;
}

}

std::unique_ptr<QtPointerLock> MakeQtPointerLock(QtRelativeMotionSink& sink) {
    return std::make_unique<DetachedPointerLock>(sink);
}
