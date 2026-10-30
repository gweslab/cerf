#pragma once

#include <cstdint>

namespace cerffrontend {

/* Windows SDK WinUser.h, VK_RETURN / VK_SHIFT / VK_CONTROL / VK_MENU / VK_ESCAPE / VK_DELETE /
   VK_F10 / VK_LSHIFT .. VK_RMENU; "VK_A - VK_Z are the same as ASCII 'A' - 'Z'". */
inline constexpr uint8_t kVkReturn   = 0x0D;
inline constexpr uint8_t kVkShift    = 0x10;
inline constexpr uint8_t kVkControl  = 0x11;
inline constexpr uint8_t kVkMenu     = 0x12;
inline constexpr uint8_t kVkEscape   = 0x1B;
inline constexpr uint8_t kVkLeft     = 0x25;
inline constexpr uint8_t kVkUp       = 0x26;
inline constexpr uint8_t kVkRight    = 0x27;
inline constexpr uint8_t kVkDown     = 0x28;
inline constexpr uint8_t kVkDelete   = 0x2E;
inline constexpr uint8_t kVkF        = 0x46;
inline constexpr uint8_t kVkP        = 0x50;
inline constexpr uint8_t kVkF10      = 0x79;
inline constexpr uint8_t kVkLShift   = 0xA0;
inline constexpr uint8_t kVkRShift   = 0xA1;
inline constexpr uint8_t kVkLControl = 0xA2;
inline constexpr uint8_t kVkRControl = 0xA3;
inline constexpr uint8_t kVkLMenu    = 0xA4;
inline constexpr uint8_t kVkRMenu    = 0xA5;

}
