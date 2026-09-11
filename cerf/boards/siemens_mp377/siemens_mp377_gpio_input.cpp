#include "../../socs/iop13xx/iop13xx_gpio_input.h"

#include "siemens_mp377_touch_panel.h"
#include "../board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../socs/irq_controller.h"

namespace {

class SiemensMp377GpioInput final : public Iop13xxGpioInput {
public:
    using Iop13xxGpioInput::Iop13xxGpioInput;

    bool ShouldRegister() override {
        auto* board = emu_.TryGet<BoardContext>();
        return board && board->GetBoard() == Board::SiemensMP377;
    }

    uint32_t ReadPins() override {
        return emu_.Get<siemens_mp377::SiemensMp377TouchPanel>().ReadPenDetectReg();
    }
};

REGISTER_SERVICE_AS(SiemensMp377GpioInput, Iop13xxGpioInput);

} // namespace
