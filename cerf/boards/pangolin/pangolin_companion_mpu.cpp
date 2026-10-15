#include "pangolin_companion_mpu.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "pangolin_family_id.h"
#include "../../host/keyboard_input.h"
#include "../../host/keyboard_map.h"
#include "../../host/keyboard_router.h"
#include "../../socs/sa11xx/sa11xx_sp3_uart.h"

#include <cstdint>

bool PangolinCompanionMpu::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardFamilyId() == BoardFamilyId::Pangolin;
}

void PangolinCompanionMpu::SendTouch(bool contact, uint16_t x14, uint16_t y14) {
    const uint8_t pkt[5] = {
        static_cast<uint8_t>(contact ? 0xBFu : 0xDFu),
        static_cast<uint8_t>((x14 >> 7) & 0x7Fu),
        static_cast<uint8_t>(x14 & 0x7Fu),
        static_cast<uint8_t>((y14 >> 7) & 0x7Fu),
        static_cast<uint8_t>(y14 & 0x7Fu),
    };
    emu_.Get<Sa11xxSp3Uart>().PushRxBurstNow(pkt, sizeof(pkt));
}

/* smartbook_g138_ce4_2 kbdmouse.dll sub_1B526BC: low byte 0xFA make / 0xF0 break,
   high byte the scancode. */
void PangolinCompanionMpu::SendKey(uint8_t scancode, bool down) {
    const uint8_t pkt[2] = { static_cast<uint8_t>(down ? 0xFAu : 0xF0u), scancode };
    emu_.Get<Sa11xxSp3Uart>().PushRxBurst(pkt, sizeof(pkt));
}

namespace {

class PangolinKeyboardInput : public KeyboardInput {
public:
    using KeyboardInput::KeyboardInput;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardFamilyId() == BoardFamilyId::Pangolin;
    }

    void OnReady() override { emu_.Get<KeyboardRouter>().Register(this); }
    std::wstring SourceName() const override { return L"SmartBook keyboard"; }
    const char* SourceLabelKey() const override { return "input.smartbook_keyboard"; }

    void OnHostKey(uint8_t vk, bool key_up) override {
        uint32_t code;
        if (!emu_.Get<KeyboardMap>().BaseDeviceCode(vk, code)) return;
        emu_.Get<PangolinCompanionMpu>().SendKey(
            static_cast<uint8_t>(code), !key_up);
    }
};

}

REGISTER_SERVICE(PangolinCompanionMpu);
REGISTER_SERVICE(PangolinKeyboardInput);
