#include "keyboard_input.h"

#include "../core/cerf_emulator.h"
#include "keyboard_map.h"

bool KeyboardInput::CanDeliverVk(uint8_t vk) const {
    auto* map = emu_.TryGet<KeyboardMap>();
    uint32_t code;
    return map && map->BaseDeviceCode(vk, code);
}
