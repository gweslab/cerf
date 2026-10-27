#include "qt_focus_policy.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/log.h>

#include <QApplication>
#include <QWidget>

REGISTER_SERVICE(QtFocusPolicy);

bool QtFocusPolicy::MayActivate() const {
    if (!emu_.Get<cerfcore::DeviceConfig>().no_focus) return true;
    return QApplication::activeWindow() != nullptr;
}

void QtFocusPolicy::Show(QWidget* window) const {
    if (MayActivate()) {
        window->show();
        return;
    }
    LOG(Lcd, "QtFocusPolicy: showing %p at the bottom of the stack, not activated\n",
        static_cast<void*>(window));
    window->setAttribute(Qt::WA_ShowWithoutActivating);
    window->show();
    window->lower();
}

void QtFocusPolicy::Raise(QWidget* window) const {
    if (!MayActivate()) return;
    window->raise();
    window->activateWindow();
}

void QtFocusPolicy::Focus(QWidget* widget) const {
    if (MayActivate()) widget->setFocus();
}
