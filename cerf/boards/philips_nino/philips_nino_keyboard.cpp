#include "../../core/cerf_emulator.h"
#include "../../host/keyboard_input.h"
#include "../../host/keyboard_map.h"
#include "../../host/keyboard_router.h"
#include "../../socs/pr31x00/pr31x00_io.h"
#include "philips_nino_keypad_codes.h"
#include "../board_context.h"
#include "philips_nino_family_id.h"

#include <cstdint>
#include <string>

namespace {

class PhilipsNinoKeyboard : public KeyboardInput {
public:
    using KeyboardInput::KeyboardInput;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardFamilyId() == BoardFamilyId::PhilipsNino;
    }

    void OnReady() override { emu_.Get<KeyboardRouter>().Register(this); }

    std::wstring SourceName() const override { return L"Nino buttons"; }
    const char* SourceLabelKey() const override { return "input.nino_buttons"; }

    /* A press drives the button's pin high, a release low; keybddr.dll (SYSINTR 8)
       scans the resulting edge into a VK. A general purpose I/O pin (bit 8 set)
       goes through Status 5, a multi-function I/O pin through Status 3/4. */
    void OnHostKey(uint8_t vk, bool key_up) override {
        uint32_t code;
        if (!emu_.Get<KeyboardMap>().BaseDeviceCode(vk, code)) return;
        const uint32_t pin = code & kNinoKeypadPinMask;
        if (code & kNinoKeypadIoPinFlag)
            emu_.Get<Pr31x00Io>().DriveIoInput(pin, !key_up);
        else
            emu_.Get<Pr31x00Io>().DriveMfioInput(pin, !key_up);
    }
};

}  // namespace

REGISTER_SERVICE(PhilipsNinoKeyboard);
