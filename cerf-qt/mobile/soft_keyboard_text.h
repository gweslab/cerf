#pragma once

#include "../qt_key_input.h"

#include <QString>

#include <cstdint>

struct TypedKey {
    uint8_t vk    = 0;
    bool    shift = false;
};

bool KeyForCharacter(char32_t character, TypedKey& out);
void TypeText(const QString& text, const QtKeyInput::KeySink& press);
