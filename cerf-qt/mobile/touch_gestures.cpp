#include "touch_gestures.h"

#include "android_view_configuration.h"

#include <QEventPoint>
#include <QGuiApplication>
#include <QLineF>
#include <QStyleHints>
#include <QTouchEvent>

#include <algorithm>

namespace {

constexpr int       kDoubleClickPaceMs = 50;
constexpr qsizetype kThreeFingers      = 3;

double Slop() { return QGuiApplication::styleHints()->startDragDistance(); }

int HoldDelay(qint64 held_ms) { return static_cast<int>(held_ms); }

}

TouchGestures::TouchGestures(TouchGestureHost& host)
    : host_(host),
      double_tap_min_ms_(AndroidDoubleTapMinTimeMs()),
      double_tap_timeout_ms_(AndroidDoubleTapTimeoutMs()),
      double_tap_slop_px_(AndroidDoubleTapSlopPx()) {
    hold_timer_.setSingleShot(true);
    release_timer_.setSingleShot(true);
    QObject::connect(&hold_timer_, &QTimer::timeout, &context_, [this] { OnHold(); });
    QObject::connect(&release_timer_, &QTimer::timeout, &context_, [this] { Advance(); });
}

void TouchGestures::Advance() {
    release_timer_.stop();
    switch (release_) {
    case Release::kNone:
        return;
    case Release::kPen:
        release_ = Release::kNone;
        host_.PenUp(pen_up_at_);
        return;
    case Release::kButton:
        release_  = Release::kNone;
        tap_open_ = false;
        host_.PointerButton(pending_up_, false);
        return;
    case Release::kSecondDown:
        release_ = Release::kSecondUp;
        host_.PointerButton(GestureButton::kLeft, true);
        release_timer_.start(kDoubleClickPaceMs);
        return;
    case Release::kSecondUp:
        release_ = Release::kNone;
        host_.PointerButton(GestureButton::kLeft, false);
        return;
    case Release::kPenRight:
        release_ = Release::kNone;
        host_.PenRightUp();
        return;
    }
}

void TouchGestures::FlushClick() {
    while (release_ != Release::kNone) Advance();
}

void TouchGestures::Click(GestureButton button, qint64 held_ms) {
    FlushClick();
    host_.PointerButton(button, true);
    pending_up_ = button;
    release_    = Release::kButton;
    release_timer_.start(HoldDelay(held_ms));
}

void TouchGestures::PenTap(QPointF at, qint64 held_ms) {
    FlushClick();
    host_.PenDown(at);
    pen_up_at_ = at;
    release_   = Release::kPen;
    release_timer_.start(HoldDelay(held_ms));
}

void TouchGestures::PenRightClick(QPointF at, qint64 held_ms) {
    FlushClick();
    host_.PenRightDown(at);
    release_ = Release::kPenRight;
    release_timer_.start(HoldDelay(held_ms));
}

bool TouchGestures::IsDoubleTap(QPointF at) const {
    if (!last_tap_) return false;
    const qint64 since = since_tap_.elapsed();
    return since >= double_tap_min_ms_ && since <= double_tap_timeout_ms_ &&
           QLineF(*last_tap_, at).length() * host_.Dpr() < double_tap_slop_px_;
}

void TouchGestures::BeginOne(int id, QPointF at) {
    primary_id_ = id;
    start_      = at;
    last_       = at;
    moved_      = false;
    held_       = false;
    since_down_.start();
    state_ = host_.DirectPen() ? State::kPenPending : State::kPointer;
    const bool double_tap = IsDoubleTap(at);
    double_tap_ = state_ == State::kPointer && tap_open_ && double_tap;
    pen_snap_   = state_ == State::kPenPending && double_tap && host_.DoubleTapHelper() ? last_tap_ : std::nullopt;
    last_tap_.reset();
    if (double_tap_) release_timer_.stop();
    else             FlushClick();
    hold_timer_.start(QGuiApplication::styleHints()->mousePressAndHoldInterval());
}

void TouchGestures::StartPen() {
    hold_timer_.stop();
    state_      = State::kPen;
    pen_lag_ms_ = since_down_.elapsed();
    host_.PenDown(start_);
}

void TouchGestures::HoldButton() {
    held_ = true;
    if (double_tap_) {
        release_  = Release::kNone;
        tap_open_ = false;
        return;
    }
    FlushClick();
    host_.PointerButton(GestureButton::kLeft, true);
}

void TouchGestures::ReleaseHeld() {
    held_ = false;
    host_.PointerButton(GestureButton::kLeft, false);
}

void TouchGestures::MoveOne(QPointF at) {
    if (state_ == State::kPen) {
        host_.PenMove(at);
        last_ = at;
        return;
    }
    if (!moved_ && QLineF(start_, at).length() < Slop()) return;
    if (state_ == State::kPenPending) {
        StartPen();
        host_.PenMove(at);
        last_ = at;
        return;
    }
    if (!moved_) {
        hold_timer_.stop();
        if (double_tap_ && !held_) HoldButton();
    }
    moved_ = true;
    host_.PointerMoveBy(at - last_);
    last_ = at;
}

void TouchGestures::EndOne(QPointF at) {
    hold_timer_.stop();
    if (state_ == State::kPenPending) {
        const QPointF tap = pen_snap_.value_or(start_);
        PenTap(tap, since_down_.elapsed());
        last_tap_ = tap;
        since_tap_.start();
    } else if (state_ == State::kPen) {
        pen_up_at_ = at;
        release_   = Release::kPen;
        release_timer_.start(HoldDelay(pen_lag_ms_));
    } else if (held_) {
        ReleaseHeld();
    } else if (double_tap_) {
        release_  = Release::kSecondDown;
        tap_open_ = false;
        host_.PointerButton(GestureButton::kLeft, false);
        release_timer_.start(kDoubleClickPaceMs);
    } else if (!moved_) {
        Click(GestureButton::kLeft, double_tap_timeout_ms_);
        tap_open_ = true;
        last_tap_ = start_;
        since_tap_.start();
    }
    state_      = State::kIdle;
    primary_id_ = -1;
    double_tap_ = false;
}

void TouchGestures::OnHold() {
    if (state_ == State::kPenPending) {
        StartPen();
        return;
    }
    if (state_ != State::kPointer || moved_) return;
    HoldButton();
}

void TouchGestures::BeginPinch(QPointF a, QPointF b) {
    hold_timer_.stop();
    if (state_ == State::kPen) host_.PenCancel();
    if (state_ == State::kPointer && held_) ReleaseHeld();
    FlushClick();
    double_tap_    = false;
    state_         = State::kPinch;
    pinch_start_a_ = a;
    pinch_start_b_ = b;
    pinch_moved_   = false;
    pinch_points_  = 0;
    since_down_.start();
    host_.PinchBegin((a + b) / 2.0, QLineF(a, b).length());
}

void TouchGestures::EndPinch() {
    host_.PinchEnd();
    if (!pinch_moved_ && pinch_points_ >= kThreeFingers) host_.ThreeFingerTap();
    else if (!pinch_moved_ && host_.DirectPen()) PenRightClick(pinch_start_a_, since_down_.elapsed());
    else if (!pinch_moved_)                      Click(GestureButton::kRight, since_down_.elapsed());
    state_ = State::kDrain;
}

void TouchGestures::TrackPinchPoints(const QList<QEventPoint>& points) {
    pinch_points_ = std::max(pinch_points_, points.size());
    for (qsizetype i = 2; i < points.size(); ++i)
        if (QLineF(points[i].pressPosition(), points[i].position()).length() >= Slop()) pinch_moved_ = true;
}

void TouchGestures::OnTouch(QTouchEvent* event) {
    const QList<QEventPoint>& points = event->points();
    if (state_ == State::kPinch) {
        if (points.size() < 2 || event->type() == QEvent::TouchEnd ||
            points[0].state() == QEventPoint::Released || points[1].state() == QEventPoint::Released) {
            EndPinch();
        } else {
            const QPointF a = points[0].position();
            const QPointF b = points[1].position();
            if (QLineF(a, pinch_start_a_).length() >= Slop() || QLineF(b, pinch_start_b_).length() >= Slop())
                pinch_moved_ = true;
            TrackPinchPoints(points);
            host_.PinchUpdate((a + b) / 2.0, QLineF(a, b).length());
        }
    } else if (points.size() >= 2 && state_ != State::kDrain) {
        BeginPinch(points[0].position(), points[1].position());
        TrackPinchPoints(points);
    } else if (state_ == State::kIdle && points.size() == 1 &&
               points[0].state() == QEventPoint::Pressed) {
        BeginOne(points[0].id(), points[0].position());
    } else if (state_ == State::kPenPending || state_ == State::kPen || state_ == State::kPointer) {
        for (const QEventPoint& p : points) {
            if (p.id() != primary_id_) continue;
            if (p.state() == QEventPoint::Released) EndOne(p.position());
            else                                    MoveOne(p.position());
        }
    }
    if (event->type() == QEvent::TouchEnd && state_ == State::kDrain) state_ = State::kIdle;
    event->accept();
}

void TouchGestures::Cancel() {
    hold_timer_.stop();
    if (state_ == State::kPen) host_.PenCancel();
    if (state_ == State::kPointer && held_) ReleaseHeld();
    if (state_ == State::kPinch) host_.PinchEnd();
    if (double_tap_) FlushClick();
    state_      = State::kIdle;
    primary_id_ = -1;
    double_tap_ = false;
}

void TouchGestures::Flush() { FlushClick(); }
