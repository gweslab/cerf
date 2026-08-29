#include "../../core/cerf_emulator.h"
#include "../../host/keyboard_map.h"
#include "../board_context.h"

#include <vector>

namespace {

/* device_code is the GIU pin. casio_cassiopeia_e55 keybddr.dll sub_14E37C4 @0x14E37C4 forms
   scan lane N from GIUPIODL bit N+5, and lanes 9-12 from GIUPIODH D13/D15/D14 and GIUPIODL
   D14; sub_14E25A0 @0x14E25A0 maps lane N to the guest VK at 0x14E0C27 + N + 1. */
const std::vector<KeyBinding> kBindings = {
    { 0x0D,  6, L"Action", 0, 0 },
    { 0x1B,  7, L"Cancel", 0, 0 },
    { 0x70,  8, L"App1",   0, 0 },
    { 0x71,  9, L"App2",   0, 0 },
    { 0x72, 10, L"App3",   0, 0 },
    { 0x73, 11, L"App4",   0, 0 },
    { 0x22, 12, L"Down",   0, 0 },
    { 0x21, 13, L"Up",     0, 0 },
    { 0x26, 29, nullptr,   0, 0 },
    { 0x28, 14, nullptr,   0, 0 },
    { 0x25, 31, nullptr,   0, 0 },
    { 0x27, 30, nullptr,   0, 0 },
};

class CasioCassiopeiaE55KeyboardMap : public KeyboardMap {
public:
    using KeyboardMap::KeyboardMap;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::CasioCassiopeiaE55;
    }

    const std::vector<KeyBinding>& Bindings() const override { return kBindings; }
};

}

REGISTER_SERVICE_AS(CasioCassiopeiaE55KeyboardMap, KeyboardMap);
