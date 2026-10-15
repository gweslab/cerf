#include "../../core/cerf_emulator.h"
#include "../../host/keyboard_input.h"
#include "../../host/keyboard_map.h"
#include "../../host/keyboard_router.h"
#include "philips_velo_1_keyboard_ec.h"
#include "../board_context.h"
#include "philips_velo_1_family_id.h"

#include <cstdint>

namespace {

class PhilipsVelo1KeyboardInput : public KeyboardInput {
public:
    using KeyboardInput::KeyboardInput;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardFamilyId() == BoardFamilyId::PhilipsVelo1;
    }

    void OnReady() override { emu_.Get<KeyboardRouter>().Register(this); }

    std::wstring SourceName() const override { return L"Velo keyboard"; }
    const char* SourceLabelKey() const override { return "input.velo_keyboard"; }

    void OnHostKey(uint8_t vk, bool key_up) override {
        uint32_t code;
        if (!emu_.Get<KeyboardMap>().BaseDeviceCode(vk, code)) return;
        emu_.Get<PhilipsVelo1KeyboardEc>().InjectKey(static_cast<uint8_t>(code), key_up);
    }
};

}  // namespace

REGISTER_SERVICE(PhilipsVelo1KeyboardInput);
