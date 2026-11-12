#include "menu_drag.h"

#include <QEvent>
#include <QMouseEvent>
#include <QQuickItem>

namespace {

class OuterGrabRelease : public QObject {
public:
    explicit OuterGrabRelease(QQuickWindow& popup) : QObject(&popup), popup_(popup) {}

protected:
    bool eventFilter(QObject*, QEvent* event) override {
        if (event->type() != QEvent::MouseMove) return false;
        auto* move = static_cast<QMouseEvent*>(event);
        if (move->buttons() == Qt::NoButton) return false;
        const QEventPoint& point   = move->point(0);
        auto*              grabber = qobject_cast<QQuickItem*>(move->exclusiveGrabber(point));
        if (grabber != nullptr && grabber->window() != &popup_) move->setExclusiveGrabber(point, nullptr);
        return false;
    }

private:
    QQuickWindow& popup_;
};

}

void MenuDrag::Track(QQuickWindow* popup) {
    for (QObject* child : popup->children()) {
        if (dynamic_cast<OuterGrabRelease*>(child) != nullptr) return;
    }
    popup->installEventFilter(new OuterGrabRelease(*popup));
}
