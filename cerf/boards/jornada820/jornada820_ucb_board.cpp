#include "../../peripherals/philips_ucb1200/ucb1x00_board.h"

#include "../board_context.h"
#include "jornada_820_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"

#include <cstdint>

namespace {

constexpr uint8_t  kAuxBackup        = 0;
constexpr uint16_t kBackupAdcHealthy = 0x0200u;

class Jornada820UcbBoard : public Ucb1x00Board {
public:
    using Ucb1x00Board::Ucb1x00Board;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Jornada820;
    }

    uint16_t AuxAdc(uint8_t channel) override {
        if (channel == kAuxBackup) return kBackupAdcHealthy;
        emu_.Get<Fatal>().Die("jornada820: UCB AD%u conversion; only the AD0 backup cell "
                              "is modelled on this board", channel);
    }

    uint16_t TouchAdcX() override { DieTouchConversion("X"); }
    uint16_t TouchAdcY() override { DieTouchConversion("Y"); }
    uint16_t TouchAdcPressure() override { DieTouchConversion("pressure"); }

    uint16_t IoInputs(uint16_t input_mask) override {
        emu_.Get<Fatal>().Die("jornada820: UCB IO_DATA read with input pins 0x%03X; no "
                              "codec I/O input is modelled on this board", input_mask);
    }

    bool AdcExternalReference() const override { return false; }

    bool TsCrLowBitsSetOnTouch() const override { return true; }
    void OnIrqOutChanged(bool asserted) override {
        emu_.Get<Fatal>().Die(
            "jornada820: UCB IRQOUT -> %d; the pin the codec interrupt drives on "
            "this board is not modelled", asserted ? 1 : 0);
    }

    SocResetReach CodecSocResetReach() const override { return SocResetReach::Unknown; }

private:
    [[noreturn]] void DieTouchConversion(const char* what) {
        emu_.Get<Fatal>().Die("jornada820: UCB touch plate %s conversion; no touch plate "
                              "is modelled on this board's codec", what);
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(Jornada820UcbBoard, Ucb1x00Board);
