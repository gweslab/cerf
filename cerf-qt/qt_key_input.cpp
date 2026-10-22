#include "qt_key_input.h"

#include "qt_key_position.h"

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
