#include "button_row.h"

#include "canvas_input.h"
#include "host_key_name.h"
#include "host_virtual_keys.h"
#include "pc_key_legend.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/keyboard_input.h>
#include <cerfcore/host/keyboard_router.h>

namespace cerffrontend {

REGISTER_SERVICE(ButtonRow);

namespace {

bool IsArrow(uint8_t vk) { return vk == kVkLeft || vk == kVkUp || vk == kVkRight || vk == kVkDown; }

}

bool ButtonRow::Shown(const cerfcore::SpecialKey& key) const {
    if (!keys_shown_ || key.vk == kVkReturn) return false;
    if (key.guest_label == nullptr) return true;
    const char* legend = PcKeyLegend(key.vk);
    if (legend != nullptr && SameKeyName(key.guest_label, legend)) return true;
    return SameKeyName(key.guest_label, HostKeyName(key.vk));
}

void ButtonRow::SetKeysShown(bool shown) {
    if (shown == keys_shown_) return;
    keys_shown_ = shown;
    if (shown) return;
    CancelPress();
    ReleaseHeld();
}

void ButtonRow::ReleaseHeld() {
    for (size_t vk = 0; vk < held_.size(); ++vk)
        if (held_.test(vk)) SendKey(static_cast<uint8_t>(vk), true);
    held_.reset();
}

std::string ButtonRow::Label(const cerfcore::SpecialKey& key) const {
    if (key.guest_label != nullptr) return key.guest_label;
    if (IsArrow(key.vk)) return HostKeyName(key.vk);
    if (const char* legend = PcKeyLegend(key.vk)) return legend;
    return HostKeyName(key.vk);
}

std::vector<RowButton> ButtonRow::Buttons() {
    cerfcore::KeyboardInput* source = emu_.Get<cerfcore::KeyboardRouter>().Active();
    if (source != source_) {
        CancelPress();
        ReleaseHeld();
        source_ = source;
    }
    std::vector<RowButton> out;
    if (source == nullptr) return out;
    for (const cerfcore::SpecialKey& key : source->SpecialKeys()) {
        if (!Shown(key)) continue;
        RowButton b;
        b.vk    = key.vk;
        b.label = Label(key);
        b.named = key.guest_label != nullptr;
        b.held  = held_.test(key.vk);
        out.push_back(std::move(b));
    }
    return out;
}

void ButtonRow::PressAt(size_t index) {
    const std::vector<RowButton> buttons = Buttons();
    if (index >= buttons.size()) return;
    const RowButton& b = buttons[index];
    CancelPress();
    press_open_ = true;
    if (held_.test(b.vk)) return;
    pressed_vk_ = b.vk;
    pressing_   = true;
    SendKey(b.vk, false);
}

void ButtonRow::ReleaseAt(size_t index) {
    const std::vector<RowButton> buttons = Buttons();
    if (!press_open_ || index >= buttons.size()) return;
    press_open_        = false;
    const RowButton& b = buttons[index];
    if (pressing_ && pressed_vk_ == b.vk) {
        pressing_ = false;
        SendKey(b.vk, true);
        return;
    }
    if (held_.test(b.vk)) {
        held_.reset(b.vk);
        SendKey(b.vk, true);
    }
}

bool ButtonRow::HoldAt(size_t index) {
    const std::vector<RowButton> buttons = Buttons();
    if (!press_open_ || index >= buttons.size()) return false;
    press_open_        = false;
    const RowButton& b = buttons[index];
    if (pressing_ && pressed_vk_ == b.vk) {
        pressing_ = false;
        held_.set(b.vk);
    }
    return held_.test(b.vk);
}

void ButtonRow::CancelPress() {
    press_open_ = false;
    if (!pressing_) return;
    pressing_ = false;
    SendKey(pressed_vk_, true);
}

void ButtonRow::SendKey(uint8_t vk, bool key_up) { emu_.Get<CanvasInput>().OnKey(vk, key_up); }

}
