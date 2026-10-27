#include "button_row.h"

#include "canvas_input.h"
#include "host_key_name.h"
#include "host_virtual_keys.h"
#include "pc_keyboard_layout.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/device_buttons.h>
#include <cerfcore/host/keyboard_input.h>
#include <cerfcore/host/keyboard_router.h>

#include <algorithm>
#include <cctype>
#include <string_view>

namespace cerffrontend {

REGISTER_SERVICE(ButtonRow);

namespace {

bool SameName(std::string_view a, std::string_view b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
               return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
           });
}

const char* PcLegend(uint8_t vk) {
    for (const KeyCap& cap : kPcKeyboard)
        if (cap.vk == vk) return cap.legend;
    return nullptr;
}

bool IsArrow(uint8_t vk) { return vk == kVkLeft || vk == kVkUp || vk == kVkRight || vk == kVkDown; }

}

bool ButtonRow::Shown(const cerfcore::SpecialKey& key) const {
    if (pc_keys_shown_) return true;
    if (key.guest_label == nullptr) return false;
    const char* legend = PcLegend(key.vk);
    if (legend != nullptr && SameName(key.guest_label, legend)) return false;
    return !SameName(key.guest_label, HostKeyName(key.vk));
}

std::string ButtonRow::Label(const cerfcore::SpecialKey& key) const {
    if (key.guest_label != nullptr) return key.guest_label;
    if (IsArrow(key.vk)) return HostKeyName(key.vk);
    if (const char* legend = PcLegend(key.vk)) return legend;
    return HostKeyName(key.vk);
}

std::vector<RowButton> ButtonRow::Buttons() {
    cerfcore::KeyboardInput* source = emu_.Get<cerfcore::KeyboardRouter>().Active();
    if (source != source_) {
        CancelPress();
        for (size_t vk = 0; vk < held_.size(); ++vk)
            if (held_.test(vk)) SendKey(static_cast<uint8_t>(vk), true);
        held_.reset();
        source_ = source;
    }
    std::vector<RowButton> out;
    if (source != nullptr) {
        for (const cerfcore::SpecialKey& key : source->SpecialKeys()) {
            if (!Shown(key)) continue;
            RowButton b;
            b.vk    = key.vk;
            b.label = Label(key);
            b.named = key.guest_label != nullptr;
            b.held  = held_.test(key.vk);
            out.push_back(std::move(b));
        }
    }
    if (auto* device = emu_.TryGet<cerfcore::DeviceButtons>()) {
        const std::vector<cerfcore::DeviceButtons::ButtonGroup> groups = device->ButtonGroups();
        for (size_t g = 0; g < groups.size(); ++g) {
            for (size_t i = 0; i < groups[g].size(); ++i) {
                RowButton b;
                b.kind        = RowButton::Kind::kAction;
                b.group       = g;
                b.item        = i;
                b.label       = groups[g][i].label;
                b.group_start = i == 0 && !out.empty();
                out.push_back(std::move(b));
            }
        }
    }
    return out;
}

void ButtonRow::PressAt(size_t index) {
    const std::vector<RowButton> buttons = Buttons();
    if (index >= buttons.size()) return;
    const RowButton& b = buttons[index];
    CancelPress();
    press_open_ = true;
    if (b.kind != RowButton::Kind::kKey || held_.test(b.vk)) return;
    pressed_vk_ = b.vk;
    pressing_   = true;
    SendKey(b.vk, false);
}

void ButtonRow::ReleaseAt(size_t index) {
    const std::vector<RowButton> buttons = Buttons();
    if (!press_open_ || index >= buttons.size()) return;
    press_open_        = false;
    const RowButton& b = buttons[index];
    if (b.kind == RowButton::Kind::kAction) {
        RunAction(b);
        return;
    }
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
    if (b.kind == RowButton::Kind::kAction) {
        RunAction(b);
        return false;
    }
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

void ButtonRow::RunAction(const RowButton& button) {
    emu_.Get<cerfcore::DeviceButtons>().ButtonGroups().at(button.group).at(button.item).press();
}

}
