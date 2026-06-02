#include "../../host/touch_input.h"

#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"

#include "odo_arm720_touch_sound.h"

namespace {

class OdoArm720TouchInput : public TouchInput {
public:
    using TouchInput::TouchInput;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::OdoArm720;
    }

    void OnPenDown    (int x, int y) override {
        emu_.Get<OdoArm720TouchSound>().OnPenDown(x, y);
    }
    void OnPenMove    (int x, int y) override {
        emu_.Get<OdoArm720TouchSound>().OnPenMove(x, y);
    }
    void OnPenUp      (int x, int y) override {
        (void)x; (void)y;
        emu_.Get<OdoArm720TouchSound>().OnPenUp();
    }
    void OnCaptureLost() override {
        emu_.Get<OdoArm720TouchSound>().OnPenUp();
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(OdoArm720TouchInput, TouchInput);
