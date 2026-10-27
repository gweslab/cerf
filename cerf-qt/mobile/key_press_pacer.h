#pragma once

#include "../qt_key_input.h"
#include "press_pacing.h"

#include <QElapsedTimer>
#include <QTimer>

#include <deque>

class KeyPressPacer {
public:
    explicit KeyPressPacer(QtKeyInput::KeySink sink);

    void Submit(const QtHostKey& key, bool key_up, bool paced);
    void Drop();

private:
    struct KeyEvent {
        QtHostKey key;
        bool      key_up;
    };

    void Drain();

    QtKeyInput::KeySink  sink_;
    PressPacing          pacing_;
    std::deque<KeyEvent> pending_;
    QElapsedTimer        clock_;
    QTimer               due_;
};
