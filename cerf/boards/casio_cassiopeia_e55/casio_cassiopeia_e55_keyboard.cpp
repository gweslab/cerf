#include "../../core/cerf_emulator.h"
#include "../../host/keyboard_input.h"
#include "../../host/keyboard_map.h"
#include "../../host/keyboard_router.h"
#include "../../socs/vr41xx/vr41xx_giu.h"
#include "../board_context.h"

#include <cstdint>
#include <string>

namespace {

/* casio_cassiopeia_e55 keybddr.dll sub_14E37C4 @0x14E37C4 folds GIUPIODH D13/D15/D14 and
   GIUPIODL D14 into scan lanes 9-12 and inverts them with ^0x1E00. */
constexpr int kKeypadPins[] = {6, 7, 8, 9, 10, 11, 12, 13, 14, 29, 30, 31};

class CasioCassiopeiaE55Keyboard : public KeyboardInput {
public:
    using KeyboardInput::KeyboardInput;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::CasioCassiopeiaE55;
    }

    void OnReady() override {
        auto& giu = emu_.Get<Vr41xxGiu>();
        for (int pin : kKeypadPins) giu.SetPinLevel(pin, true);
        emu_.Get<KeyboardRouter>().Register(this);
    }

    std::wstring SourceName() const override { return L"Cassiopeia buttons"; }

    /* casio_cassiopeia_e55 keybddr.dll sub_14E37C4 @0x14E37C4 inverts scan lanes 1-8 with
       ^0x3FC0; NetBSD sys/arch/hpcmips/conf/VR41XX:315-322 gives ports 6-13 "active 0". */
    void OnHostKey(uint8_t vk, bool key_up) override {
        uint32_t pin = 0;
        if (!emu_.Get<KeyboardMap>().BaseDeviceCode(vk, pin)) return;
        emu_.Get<Vr41xxGiu>().SetPinLevel(static_cast<int>(pin), key_up);
    }
};

}

REGISTER_SERVICE(CasioCassiopeiaE55Keyboard);
