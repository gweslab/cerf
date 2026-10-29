#pragma once

#include "touch_gestures.h"

#include "../canvas_input.h"

#include <QPointF>
#include <QRectF>

#include <cstdint>

class GesturePointerHost {
public:
    virtual ~GesturePointerHost() = default;

    virtual bool   RelativeGuestPointer() const = 0;
    virtual QRectF VisibleImage() const = 0;
    virtual double GuestScale() const = 0;
    virtual void   SendCanvasMouse(cerffrontend::CanvasMouse::Kind kind, cerffrontend::MouseButton button,
                                   QPointF device_at, uint32_t held) = 0;
    virtual void   SendRelative(int dx, int dy, uint32_t buttons) = 0;
};

class GesturePointer {
public:
    explicit GesturePointer(GesturePointerHost& host) : host_(host) {}

    QPointF Position() const { return cursor_; }
    void    Center();
    void    Settle();
    bool    MoveBy(QPointF device_delta);
    void    Button(GestureButton button, bool down);

private:
    bool RelativePath() const;
    void Clamp();
    void SendMove();

    GesturePointerHost& host_;
    QPointF             cursor_;
    QPointF             relative_rest_;
    uint32_t            held_          = 0;
    uint32_t            relative_held_ = 0;
};
