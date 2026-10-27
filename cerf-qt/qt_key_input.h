#pragma once

#include <cerfcore/core/service.h>

#include <bitset>
#include <cstdint>
#include <functional>

class QKeyEvent;

struct QtHostKey {
    uint8_t vk       = 0;
    uint8_t sided_vk = 0;
    bool    toggle   = false;
};

class QtKeyInput : public cerfcore::Service {
public:
    using cerfcore::Service::Service;
    using KeySink = std::function<void(const QtHostKey& key, bool key_up)>;

    bool Translate(const QKeyEvent* event, QtHostKey& out);
    void Note(const QtHostKey& key, bool key_up);
    bool Down(uint8_t vk) const { return down_.test(vk); }
    void Route(QKeyEvent* event, bool key_up, bool host_owns_system_keys);
    void RouteTo(const QKeyEvent* event, bool key_up, const KeySink& sink);
    bool Deliver(const QtHostKey& key, bool key_up, bool host_owns_system_keys);

    template <class Deliver>
    void ForEachTransition(const QtHostKey& key, bool key_up, Deliver deliver) const {
        if (!key.toggle) {
            deliver(key_up);
            return;
        }
        deliver(false);
        deliver(true);
    }

private:
    std::bitset<256> down_;
};
