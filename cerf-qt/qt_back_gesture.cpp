#include "qt_back_gesture.h"

#include <QCoreApplication>
#include <QKeyEvent>
#include <QMetaObject>
#include <QVariant>

QtBackGesture::QtBackGesture(QCoreApplication& app) { app.installEventFilter(this); }

bool QtBackGesture::eventFilter(QObject* watched, QEvent* event) {
    const QEvent::Type type = event->type();
    if ((type != QEvent::KeyPress && type != QEvent::KeyRelease) || !watched->isWindowType() || delivering_ ||
        static_cast<QKeyEvent*>(event)->key() != Qt::Key_Back)
        return QObject::eventFilter(watched, event);
    if (type == QEvent::KeyPress) {
        if (depth_ == 0) {
            depth_ = 1;
            return Begin(watched, event);
        }
        if (!static_cast<QKeyEvent*>(event)->isAutoRepeat()) ++depth_;
    } else if (depth_ == 0) {
        return QObject::eventFilter(watched, event);
    } else {
        --depth_;
    }
    if (!handled_) return QObject::eventFilter(watched, event);
    event->accept();
    return true;
}

bool QtBackGesture::Begin(QObject* window, QEvent* event) {
    event->ignore();
    delivering_ = true;
    QCoreApplication::sendEvent(window, event);
    delivering_ = false;
    handled_    = event->isAccepted();
    if (!handled_ && window->metaObject()->indexOfMethod("goBack()") >= 0) {
        QVariant result;
        QMetaObject::invokeMethod(window, "goBack", Q_RETURN_ARG(QVariant, result));
        handled_ = result.toBool();
    }
    event->setAccepted(handled_);
    return true;
}
