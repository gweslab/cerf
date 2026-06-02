#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../host/keyboard_input.h"
#include "../../socs/imx31/imx31_kpp.h"

#include <cstdint>

namespace {

/* Host VK -> KPP matrix cell. pyxis_keybd.dll's cell->VK table (nk.bin, decompiled)
   is cell0..3 = LEFT/UP/DOWN/RIGHT, cell5 = VK_BACK, cell6 = VK_RETURN (OK),
   cell15 = VK_MEDIA_PLAY_PAUSE; cell = 5*col+row. Each host key maps to the cell
   that re-emits the matching action VK. */
struct Cell { uint8_t col, row; bool valid; };

constexpr Cell MapVk(uint8_t vk) {
    switch (vk) {
        case 0x25: return {0, 0, true};   /* VK_LEFT   -> cell 0  */
        case 0x26: return {0, 1, true};   /* VK_UP     -> cell 1  */
        case 0x28: return {0, 2, true};   /* VK_DOWN   -> cell 2  */
        case 0x27: return {0, 3, true};   /* VK_RIGHT  -> cell 3  */
        case 0x0D: return {1, 1, true};   /* VK_RETURN -> cell 6  (OK/center) */
        case 0x08:                        /* VK_BACK (Backspace) */
        case 0x1B: return {1, 0, true};   /* VK_ESCAPE -> cell 5  (Back) */
        case 0x20:                        /* VK_SPACE */
        case 0xB3: return {3, 0, true};   /* VK_MEDIA_PLAY_PAUSE -> cell 15 */
    }
    return {0, 0, false};
}

class ZuneKeelKeyboardInput : public KeyboardInput {
public:
    using KeyboardInput::KeyboardInput;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::ZuneKeel;
    }

    void OnHostKey(uint8_t vk, bool key_up) override {
        const Cell c = MapVk(vk);
        if (!c.valid) return;
        emu_.Get<Imx31Kpp>().SetMatrixKey(c.col, c.row, !key_up);
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(ZuneKeelKeyboardInput, KeyboardInput);
