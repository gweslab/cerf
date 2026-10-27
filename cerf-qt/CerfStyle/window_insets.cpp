#include "window_insets.h"

#include <QGuiApplication>
#include <QInputMethod>
#include <QMetaMethod>
#include <QMetaProperty>
#include <QQuickWindow>
#include <QVariant>
#include <QtMath>

#include <algorithm>

WindowInsets::WindowInsets(QObject* attachee) : QObject(attachee), attachee_(attachee) {
    const QMetaObject* type  = attachee->metaObject();
    const int          index = type->indexOfProperty("parent");
    if (qobject_cast<QQuickItem*>(attachee) == nullptr && index >= 0 && type->property(index).hasNotifySignal())
        connect(attachee, type->property(index).notifySignal(), this,
                metaObject()->method(metaObject()->indexOfSlot("FollowItem()")));
    QInputMethod* keyboard = QGuiApplication::inputMethod();
    connect(keyboard, &QInputMethod::keyboardRectangleChanged, this, &WindowInsets::Read);
    connect(keyboard, &QInputMethod::visibleChanged, this, &WindowInsets::Read);
    connect(qGuiApp, &QGuiApplication::focusWindowChanged, this, &WindowInsets::Read);
    FollowItem();
}

WindowInsets* WindowInsets::qmlAttachedProperties(QObject* attachee) { return new WindowInsets(attachee); }

void WindowInsets::SetGap(qreal gap) {
    if (gap == gap_) return;
    gap_ = gap;
    Q_EMIT changed();
}

qreal WindowInsets::WithGap(qreal inset) const { return std::max(inset, gap_); }

qreal WindowInsets::LeftMargin() const { return WithGap(Left()); }

qreal WindowInsets::TopMargin() const { return WithGap(Top()); }

qreal WindowInsets::RightMargin() const { return WithGap(Right()); }

qreal WindowInsets::BottomMargin() const { return WithGap(Bottom()); }

void WindowInsets::FollowItem() {
    QQuickItem* item = qobject_cast<QQuickItem*>(attachee_);
    if (item == nullptr) item = attachee_->property("parent").value<QQuickItem*>();
    disconnect(item_window_);
    item_ = item;
    if (item != nullptr) item_window_ = connect(item, &QQuickItem::windowChanged, this, &WindowInsets::FollowWindow);
    FollowWindow();
}

void WindowInsets::FollowWindow() {
    QWindow* window = qobject_cast<QWindow*>(attachee_);
    if (window == nullptr && item_ != nullptr) window = item_->window();
    disconnect(window_margins_);
    disconnect(window_height_);
    window_ = window;
    if (window != nullptr) window_height_ = connect(window, &QWindow::heightChanged, this, &WindowInsets::Read);
#if QT_VERSION >= QT_VERSION_CHECK(6, 9, 0)
    if (window != nullptr)
        window_margins_ = connect(window, &QWindow::safeAreaMarginsChanged, this, &WindowInsets::Read);
#endif
    Read();
}

void WindowInsets::Read() {
    QMargins margins;
#if QT_VERSION >= QT_VERSION_CHECK(6, 9, 0)
    if (window_ != nullptr) margins = window_->safeAreaMargins();
#endif
    const QInputMethod* keyboard = QGuiApplication::inputMethod();
    if (window_ != nullptr && keyboard->isVisible() && QGuiApplication::focusWindow() == window_) {
        QRectF keys = keyboard->keyboardRectangle();
#if defined(Q_OS_ANDROID)
        const qreal ratio = window_->devicePixelRatio();
        keys              = QRectF(keys.topLeft() / ratio, keys.size() / ratio);
#endif
        if (keys.isValid()) margins.setBottom(std::max(margins.bottom(), qCeil(window_->height() - keys.top())));
    }
    if (margins == margins_) return;
    margins_ = margins;
    Q_EMIT changed();
}
