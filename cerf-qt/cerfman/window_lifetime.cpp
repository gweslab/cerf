#include "window_lifetime.h"

#include <QEvent>
#include <QMetaObject>

namespace {

class CloseWatch final : public QObject {
public:
    explicit CloseWatch(QWindow& window) : QObject(&window) { window.installEventFilter(this); }

    bool eventFilter(QObject* watched, QEvent* event) override {
        if (event->type() == QEvent::Close) {
            auto* window = static_cast<QWindow*>(watched);
            QMetaObject::invokeMethod(
                window, [window] { if (!window->isVisible()) window->deleteLater(); }, Qt::QueuedConnection);
        }
        return false;
    }
};

}

void WindowLifetime::DeleteWhenClosed(QWindow* window) const { new CloseWatch(*window); }
