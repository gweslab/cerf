#pragma once

#include <QElapsedTimer>
#include <QObject>
#include <QPointF>
#include <QTimer>

#include <cstdint>
#include <optional>

class QTouchEvent;

enum class GestureButton { kLeft, kRight };

class TouchGestureHost {
public:
    virtual ~TouchGestureHost() = default;

    virtual bool  DirectPen() const = 0;
    virtual bool  DoubleTapHelper() const = 0;
    virtual qreal Dpr() const = 0;
    virtual void PenDown(QPointF at) = 0;
    virtual void PenMove(QPointF at) = 0;
    virtual void PenUp(QPointF at) = 0;
    virtual void PenCancel() = 0;
    virtual void PenRightDown(QPointF at) = 0;
    virtual void PenRightUp() = 0;
    virtual void PointerMoveBy(QPointF delta) = 0;
    virtual void PointerButton(GestureButton button, bool down) = 0;
    virtual void PinchBegin(QPointF centroid, double distance) = 0;
    virtual void PinchUpdate(QPointF centroid, double distance) = 0;
    virtual void PinchEnd() = 0;
};

class TouchGestures {
public:
    explicit TouchGestures(TouchGestureHost& host);

    void OnTouch(QTouchEvent* event);
    void Cancel();
    void Flush();

private:
    enum class State { kIdle, kPenPending, kPen, kPointer, kPinch, kDrain };
    enum class Release { kNone, kButton, kPen, kSecondDown, kSecondUp, kPenRight };

    void BeginOne(int id, QPointF at);
    bool IsDoubleTap(QPointF at) const;
    void MoveOne(QPointF at);
    void EndOne(QPointF at);
    void StartPen();
    void HoldButton();
    void ReleaseHeld();
    void BeginPinch(QPointF a, QPointF b);
    void EndPinch();
    void OnHold();
    void Click(GestureButton button, qint64 held_ms);
    void PenTap(QPointF at, qint64 held_ms);
    void PenRightClick(QPointF at, qint64 held_ms);
    void Advance();
    void FlushClick();

    TouchGestureHost& host_;
    QObject           context_;
    QTimer            hold_timer_;
    QTimer            release_timer_;
    QElapsedTimer     since_down_;
    QElapsedTimer     since_tap_;
    const int         double_tap_min_ms_;
    const int         double_tap_timeout_ms_;
    const int         double_tap_slop_px_;
    std::optional<QPointF> last_tap_;
    std::optional<QPointF> pen_snap_;
    State             state_        = State::kIdle;
    int               primary_id_   = -1;
    QPointF           start_;
    QPointF           last_;
    bool              moved_        = false;
    bool              held_         = false;
    bool              double_tap_   = false;
    bool              tap_open_     = false;
    QPointF           pinch_start_a_;
    QPointF           pinch_start_b_;
    bool              pinch_moved_  = false;
    Release           release_      = Release::kNone;
    GestureButton     pending_up_   = GestureButton::kLeft;
    QPointF           pen_up_at_;
    qint64            pen_lag_ms_   = 0;
};
