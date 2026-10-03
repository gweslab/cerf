#include "../../peripherals/philips_ucb1200/ucb1x00_board.h"

#include "odo_arm720_touch_sound.h"
#include "../board_context.h"
#include "odo_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"

#include <cstdint>

namespace {

class OdoArm720UcbBoard : public Ucb1x00Board {
public:
    using Ucb1x00Board::Ucb1x00Board;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Odo;
    }

    uint16_t AuxAdc(uint8_t channel) override {
        emu_.Get<Fatal>().Die("odo ucb: aux ADC channel AD%u conversion; nothing on "
                              "this board is wired to it in the model", channel);
    }

    uint16_t TouchAdcX() override { DiePlateConversion("X"); }
    uint16_t TouchAdcY() override { DiePlateConversion("Y"); }
    uint16_t TouchAdcPressure() override { DiePlateConversion("pressure"); }

    uint16_t IoInputs(uint16_t input_mask) override {
        emu_.Get<Fatal>().Die("odo ucb: IO_DATA read with input pins 0x%03X; the codec I/O "
                              "pins on this board are not modelled", input_mask);
    }

    bool AdcExternalReference() const override {
        emu_.Get<Fatal>().Die("odo ucb: codec ADC conversion; the reference wiring of "
                              "VREFBYP on this board is not modelled");
    }

    bool TsCrLowBitsSetOnTouch() const override { return false; }

    void OnIrqOutChanged(bool asserted) override {
        emu_.Get<OdoArm720TouchSound>().SetUcbIrqOut(asserted);
    }

    SocResetReach CodecSocResetReach() const override { return SocResetReach::Never; }

private:
    [[noreturn]] void DiePlateConversion(const char* what) {
        emu_.Get<Fatal>().Die("odo ucb: touch plate %s conversion through the codec "
                              "ADC; this board samples the plates through ioAdcCntr",
                              what);
    }
};

}

REGISTER_SERVICE_AS(OdoArm720UcbBoard, Ucb1x00Board);
