#include "siemens_mp377_touch_panel.h"

#include "../board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../host/touch_input.h"

namespace {

class SiemensMp377TouchInput : public TouchInput {
public:
    using TouchInput::TouchInput;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::SiemensMP377;
    }

    void OnPenDown(int x, int y) override { UpdateTouch(x, y, true); }

    void OnPenMove(int x, int y) override { UpdateTouch(x, y, true); }

    void OnPenUp(int x, int y) override { UpdateTouch(x, y, false); }

    void OnCaptureLost() override {
        emu_.Get<siemens_mp377::SiemensMp377TouchPanel>().CaptureLost();
    }

private:
    void UpdateTouch(int x, int y, bool down) {
        emu_.Get<siemens_mp377::SiemensMp377TouchPanel>().UpdateHostPointer(x, y, down);
    }
};

} // namespace

REGISTER_SERVICE_AS(SiemensMp377TouchInput, TouchInput);
