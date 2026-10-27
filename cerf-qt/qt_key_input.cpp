#include "qt_key_input.h"

#include "qt_key_position.h"

#include "canvas_input.h"
#include "host_virtual_keys.h"
#include "input_capture.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>

#include <QGuiApplication>
#include <QKeyEvent>

REGISTER_SERVICE(QtKeyInput);

bool QtKeyInput::Translate(const QKeyEvent* event, QtHostKey& out) {
    uint32_t native = 0;
    switch (HostKeyPosition(event, out, native)) {
        case KeyPositionResult::kMapped:
            return true;
        case KeyPositionResult::kNoPosition:
            LOG(Cerf, "cerf-qt: Qt platform %s gives Qt key 0x%X no key position\n",
                QGuiApplication::platformName().toUtf8().constData(),
                static_cast<unsigned>(event->key()));
            return false;
        case KeyPositionResult::kNoVirtualKey:
            LOG(Cerf, "cerf-qt: host keycode %u has no Windows virtual key\n", native);
            return false;
    }
    return false;
}

void QtKeyInput::Note(const QtHostKey& key, bool key_up) {
    down_.set(key.vk, !key_up);
    down_.set(key.sided_vk, !key_up);
}

void QtKeyInput::Route(QKeyEvent* event, bool key_up, bool host_owns_system_keys) {
    RouteTo(event, key_up, [&](const QtHostKey& key, bool up) {
        if (!Deliver(key, up, host_owns_system_keys)) event->ignore();
    });
}

void QtKeyInput::RouteTo(const QKeyEvent* event, bool key_up, const KeySink& sink) {
    if (key_up && event->isAutoRepeat()) return;
    QtHostKey key;
    if (!Translate(event, key)) return;
    ForEachTransition(key, key_up, [&](bool up) { sink(key, up); });
}

bool QtKeyInput::Deliver(const QtHostKey& key, bool key_up, bool host_owns_system_keys) {
    Note(key, key_up);
    if (emu_.Get<cerffrontend::InputCapture>().OnHostKey(key.sided_vk, key_up)) return true;
    const bool system_key =
        key.vk == cerffrontend::kVkF10 || key.vk == cerffrontend::kVkMenu || Down(cerffrontend::kVkMenu);
    if (host_owns_system_keys && system_key) return false;
    emu_.Get<cerffrontend::CanvasInput>().OnKey(key.vk, key_up);
    return true;
}
