#include "soft_keyboard_text.h"

#include <cerfcore/core/log.h>
#include <cerfcore/host/character_keys.h>
#include <cerfcore/host/virtual_keys.h>

#include <QList>

void TypeText(const QString& text, const QtKeyInput::KeySink& press) {
    for (const char32_t character : text.toUcs4()) {
        cerfcore::TypedKey key;
        if (!cerfcore::KeyForCharacter(character, key)) {
            LOG(Cerf, "soft keyboard: the character U+%04X has no key\n", static_cast<unsigned>(character));
            continue;
        }
        const QtHostKey shift{cerfcore::kVkShift, cerfcore::kVkLShift, false};
        const QtHostKey typed{key.vk, key.vk, false};
        if (key.shift) press(shift, false);
        press(typed, false);
        press(typed, true);
        if (key.shift) press(shift, true);
    }
}
