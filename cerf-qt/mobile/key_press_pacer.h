#pragma once

#include "../qt_key_input.h"
#include "press_pacing.h"

#include <QElapsedTimer>
#include <QTimer>

#include <deque>

class KeyPressSink {
public:
    virtual void DeliverKey(const QtHostKey& key, bool key_up) = 0;

protected:
    ~KeyPressSink() = default;
};

class KeyPressPacer {
public:
    explicit KeyPressPacer(KeyPressSink& sink);

    void Submit(const QtHostKey& key, bool key_up, bool paced);
    void Drop();

private:
    struct KeyEvent {
        QtHostKey key;
        bool      key_up;
    };

    void Drain();

    KeyPressSink&        sink_;
    PressPacing          pacing_;
    std::deque<KeyEvent> pending_;
    QElapsedTimer        clock_;
    QTimer               due_;
};
