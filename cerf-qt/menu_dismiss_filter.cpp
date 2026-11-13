#include "menu_dismiss_filter.h"

#include <QEvent>
#include <QGuiApplication>
#include <QMouseEvent>
#include <QTimer>
#include <QTouchEvent>
#include <QWindow>

#include <algorithm>

void MenuDismissFilter::Arm() {
    armed_ = true;
    QTimer::singleShot(0, this, [this] { armed_ = false; });
}

bool MenuDismissFilter::OnPopup(const QPointF& global) {
    const QWindowList windows = QGuiApplication::topLevelWindows();
    return std::any_of(windows.cbegin(), windows.cend(), [&global](const QWindow* window) {
        return window->isVisible() && window->type() == Qt::Popup && window->geometry().contains(global.toPoint());
    });
}

bool MenuDismissFilter::SwallowMouse(const QMouseEvent& event) {
    const bool begins =
        event.type() == QEvent::MouseButtonPress || event.type() == QEvent::MouseButtonDblClick;
    if (begins && (armed_ || OnPopup(event.globalPosition()))) {
        armed_     = false;
        swallowed_ = event.button();
        return true;
    }
    if (swallowed_ == Qt::NoButton) return false;
    const bool ends   = event.type() == QEvent::MouseButtonRelease && event.button() == swallowed_;
    const bool repeat = begins && event.button() == swallowed_;
    if (ends || (!repeat && event.buttons().testFlag(swallowed_))) {
        if (ends) swallowed_ = Qt::NoButton;
        return true;
    }
    swallowed_ = Qt::NoButton;
    return false;
}

bool MenuDismissFilter::eventFilter(QObject* watched, QEvent* event) {
    switch (event->type()) {
        case QEvent::MouseButtonPress:
        case QEvent::MouseButtonDblClick:
        case QEvent::MouseMove:
        case QEvent::MouseButtonRelease:
            if (SwallowMouse(*static_cast<QMouseEvent*>(event))) return true;
            break;
        case QEvent::TouchBegin:
            touch_held_ = armed_ || OnPopup(static_cast<QTouchEvent*>(event)->points().first().globalPosition());
            armed_      = false;
            if (touch_held_) return true;
            break;
        case QEvent::TouchUpdate:
            if (touch_held_) return true;
            break;
        case QEvent::TouchEnd:
        case QEvent::TouchCancel:
            if (touch_held_) {
                touch_held_ = false;
                return true;
            }
            break;
        default:
            break;
    }
    return QObject::eventFilter(watched, event);
}
