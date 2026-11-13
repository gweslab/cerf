#include "qt_focus_policy.h"

#include "show_without_activating.h"

#include "../bring_window_to_front.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/log.h>

#include <QGuiApplication>
#include <QQuickItem>
#include <QWindow>

REGISTER_SERVICE(QtFocusPolicy);

bool QtFocusPolicy::MayActivate() const {
    if (!emu_.Get<cerfcore::DeviceConfig>().no_focus) return true;
    return QGuiApplication::focusWindow() != nullptr;
}

void QtFocusPolicy::Show(QWindow& window) const {
    if (MayActivate()) {
        window.show();
        return;
    }
    LOG(Lcd, "QtFocusPolicy: showing %p at the bottom of the stack, not activated\n", static_cast<void*>(&window));
    ShowWithoutActivating(window);
    window.lower();
}

void QtFocusPolicy::Raise(QWindow& window) const {
    if (MayActivate()) BringWindowToFront(window);
}

void QtFocusPolicy::Focus(QQuickItem& item) const {
    if (MayActivate()) item.forceActiveFocus(Qt::OtherFocusReason);
}
