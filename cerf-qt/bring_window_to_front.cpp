#include "bring_window_to_front.h"

#include <QWindow>

void BringWindowToFront(QWindow& window) {
    if (window.windowStates().testFlag(Qt::WindowMinimized)) window.showNormal();
    window.raise();
    window.requestActivate();
}
