#pragma once

#include <cerfcore/core/service.h>

#include <bitset>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace cerfcore {
class KeyboardInput;
struct SpecialKey;
}

namespace cerffrontend {

struct RowButton {
    uint8_t     vk    = 0;
    std::string label;
    bool        named = false;
    bool        held  = false;
};

class ButtonRow : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static constexpr int kHoldMs = 1000;

    void                   SetKeysShown(bool shown);
    std::vector<RowButton> Buttons();
    void                   PressAt(size_t index);
    void                   ReleaseAt(size_t index);
    bool                   HoldAt(size_t index);
    void                   CancelPress();

private:
    bool        Shown(const cerfcore::SpecialKey& key) const;
    std::string Label(const cerfcore::SpecialKey& key) const;
    void        SendKey(uint8_t vk, bool key_up);
    void        ReleaseHeld();

    cerfcore::KeyboardInput* source_        = nullptr;
    std::bitset<256>         held_;
    bool                     keys_shown_    = false;
    uint8_t                  pressed_vk_    = 0;
    bool                     pressing_      = false;
    bool                     press_open_    = false;
};

}
