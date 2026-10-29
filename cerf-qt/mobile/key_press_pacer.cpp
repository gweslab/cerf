#include "key_press_pacer.h"

#include <algorithm>

KeyPressPacer::KeyPressPacer(KeyPressSink& sink) : sink_(sink) {
    clock_.start();
    due_.setSingleShot(true);
    QObject::connect(&due_, &QTimer::timeout, [this] { Drain(); });
}

void KeyPressPacer::Submit(const QtHostKey& key, bool key_up, bool paced) {
    pending_.push_back(KeyEvent{key, key_up});
    pacing_.Push(key.vk, key_up ? KeyEdge::kUp : KeyEdge::kDown, paced);
    if (!due_.isActive()) Drain();
}

void KeyPressPacer::Drop() {
    due_.stop();
    pending_.clear();
    pacing_.Clear();
}

void KeyPressPacer::Drain() {
    while (!pending_.empty() && pacing_.PopReady(clock_.elapsed())) {
        const KeyEvent e = pending_.front();
        pending_.pop_front();
        sink_.DeliverKey(e.key, e.key_up);
    }
    if (!pending_.empty()) due_.start(static_cast<int>(std::max<qint64>(0, pacing_.HeadDue() - clock_.elapsed())));
}
