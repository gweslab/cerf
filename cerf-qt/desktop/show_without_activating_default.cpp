#include "show_without_activating.h"

#include <QEvent>
#include <QObject>
#include <QWindow>

namespace {

class FocusRelease final : public QObject {
public:
    explicit FocusRelease(QWindow& window) : QObject(&window) { window.installEventFilter(this); }

protected:
    bool eventFilter(QObject* watched, QEvent* event) override {
        auto* window = static_cast<QWindow*>(watched);
        if (event->type() == QEvent::Expose && window->isExposed()) {
            window->setFlag(Qt::WindowDoesNotAcceptFocus, false);
            deleteLater();
        }
        return false;
    }
};

}

void ShowWithoutActivating(QWindow& window) {
    window.setFlag(Qt::WindowDoesNotAcceptFocus, true);
    new FocusRelease(window);
    window.show();
}
