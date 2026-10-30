#include "surface_text_input.h"

#include "soft_keyboard_text.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/keyboard_input.h>
#include <cerfcore/host/keyboard_router.h>

#include <QInputMethodEvent>
#include <QKeyEvent>

SurfaceTextInput::SurfaceTextInput(QQuickItem& item, const cerfcore::InstanceGate& gate)
    : gate_(gate), keyboard_(item) {}

Qt::InputMethodHints SurfaceTextInput::Hints() {
    return Qt::ImhNoPredictiveText | Qt::ImhNoAutoUppercase | Qt::ImhMultiLine | Qt::ImhNoFullscreen;
}

void SurfaceTextInput::RefreshOffer() {
    gate_.Run([this](cerfcore::CerfEmulator& emu) {
        const cerfcore::KeyboardInput* active = emu.Get<cerfcore::KeyboardRouter>().Active();
        keyboard_.SetOffered(active != nullptr && active->HasLetterKeys());
    });
}

bool SurfaceTextInput::Key(const QKeyEvent* event, bool key_up) {
    if (event->key() == Qt::Key_Back) return false;
    gate_.Run([this, event, key_up](cerfcore::CerfEmulator& emu) {
        emu.Get<QtKeyInput>().RouteTo(event, key_up,
                                      [this](const QtHostKey& key, bool up) { key_pacer_.Submit(key, up, false); });
    });
    return true;
}

void SurfaceTextInput::Commit(const QInputMethodEvent* event) {
    if (gate_.Attached() && !event->commitString().isEmpty())
        TypeText(event->commitString(), [this](const QtHostKey& key, bool up) { key_pacer_.Submit(key, up, true); });
}

void SurfaceTextInput::DeliverKey(const QtHostKey& key, bool key_up) {
    gate_.Run([&](cerfcore::CerfEmulator& emu) { emu.Get<QtKeyInput>().Deliver(key, key_up, false); });
}
