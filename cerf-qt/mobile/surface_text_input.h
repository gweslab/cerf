#pragma once

#include "key_press_pacer.h"
#include "soft_keyboard_request.h"

#include <cerfcore/core/instance_gate.h>

#include <Qt>

class QInputMethodEvent;
class QKeyEvent;
class QQuickItem;

class SurfaceTextInput : public KeyPressSink {
public:
    SurfaceTextInput(QQuickItem& item, const cerfcore::InstanceGate& gate);

    static Qt::InputMethodHints Hints();

    SoftKeyboardRequest&       Keyboard() { return keyboard_; }
    const SoftKeyboardRequest& Keyboard() const { return keyboard_; }
    void                 RefreshOffer();
    void                 Drop() { key_pacer_.Drop(); }
    bool                 Key(const QKeyEvent* event, bool key_up);
    void                 Commit(const QInputMethodEvent* event);

    void DeliverKey(const QtHostKey& key, bool key_up) override;

private:
    const cerfcore::InstanceGate& gate_;
    SoftKeyboardRequest           keyboard_;
    KeyPressPacer                 key_pacer_{*this};
};
