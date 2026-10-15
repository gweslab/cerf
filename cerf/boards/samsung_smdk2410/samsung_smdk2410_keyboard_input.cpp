#include "samsung_smdk2410_keyboard_controller.h"

#include "../../boards/board_context.h"
#include "samsung_smdk2410_family_id.h"
#include "../../core/cerf_emulator.h"
#include "../../host/keyboard_input.h"
#include "../../host/keyboard_map.h"
#include "../../host/keyboard_router.h"

namespace {

constexpr uint8_t kScancodeKeyUp = 0x80u;

class SamsungSmdk2410KeyboardInput : public KeyboardInput {
public:
    using KeyboardInput::KeyboardInput;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardFamilyId() == BoardFamilyId::SamsungSmdk2410;
    }

    void OnReady() override { emu_.Get<KeyboardRouter>().Register(this); }

    std::wstring SourceName() const override { return L"DevEmu keyboard"; }
    const char* SourceLabelKey() const override { return "input.devemu_keyboard"; }

    void OnHostKey(uint8_t vk, bool key_up) override {
        uint32_t code = 0;
        if (!emu_.Get<KeyboardMap>().BaseDeviceCode(vk, code)) { return; }
        const uint8_t scancode = static_cast<uint8_t>(code & 0xFFu);
        emu_.Get<SamsungSmdk2410KeyboardController>().QueueScancode(
            key_up ? static_cast<uint8_t>(scancode | kScancodeKeyUp) : scancode);
    }
};

}

REGISTER_SERVICE(SamsungSmdk2410KeyboardInput);
