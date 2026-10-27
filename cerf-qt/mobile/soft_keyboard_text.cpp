#include "soft_keyboard_text.h"

#include "../host_virtual_keys.h"
#include "../pc_keyboard_layout.h"

#include <cerfcore/core/log.h>

#include <QList>

#include <cstring>

namespace {

constexpr char kPlainCharacters[]   = "`1234567890-=[]\\;',./";
constexpr char kShiftedCharacters[] = "~!@#$%^&*()_+{}|:\"<>?";

bool KeyForLegend(const char* legend, bool shift, TypedKey& out) {
    for (const cerffrontend::KeyCap& cap : cerffrontend::kPcKeyboard) {
        if (std::strcmp(cap.legend, legend) == 0) {
            out = {cap.vk, shift};
            return true;
        }
    }
    return false;
}

const char* NamedLegend(char32_t character) {
    switch (character) {
        case U' ':  return "Space";
        case U'\n': return "Enter";
        case U'\t': return "Tab";
        default:    return nullptr;
    }
}

}

bool KeyForCharacter(char32_t character, TypedKey& out) {
    if (const char* legend = NamedLegend(character)) return KeyForLegend(legend, false, out);
    if (character == 0 || character > 0x7F) return false;
    char c     = static_cast<char>(character);
    bool shift = false;
    if (c >= 'a' && c <= 'z') {
        c = static_cast<char>(c - 'a' + 'A');
    } else if (c >= 'A' && c <= 'Z') {
        shift = true;
    } else if (const char* at = std::strchr(kShiftedCharacters, c)) {
        c     = kPlainCharacters[at - kShiftedCharacters];
        shift = true;
    }
    const char legend[] = {c, '\0'};
    return KeyForLegend(legend, shift, out);
}

void TypeText(const QString& text, const QtKeyInput::KeySink& press) {
    for (const char32_t character : text.toUcs4()) {
        TypedKey key;
        if (!KeyForCharacter(character, key)) {
            LOG(Cerf, "soft keyboard: the character U+%04X has no key\n", static_cast<unsigned>(character));
            continue;
        }
        const QtHostKey shift{cerffrontend::kVkShift, cerffrontend::kVkLShift, false};
        const QtHostKey typed{key.vk, key.vk, false};
        if (key.shift) press(shift, false);
        press(typed, false);
        press(typed, true);
        if (key.shift) press(shift, true);
    }
}
