#include "../../peripherals/cirrus_pd6710/pd6710_card_irq_line.h"

#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"
#include "../../socs/s3c2410/s3c2410_io_port.h"

namespace {

constexpr int kPd6710CardEintNumber = 8;

class DevEmuPd6710CardIrqLine : public Pd6710CardIrqLine {
public:
    using Pd6710CardIrqLine::Pd6710CardIrqLine;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::Smdk2410DevEmu;
    }

    void Assert() override {
        emu_.Get<S3C2410IoPort>().AssertEint(kPd6710CardEintNumber);
    }
    void Deassert() override {
        emu_.Get<S3C2410IoPort>().ClearEint(kPd6710CardEintNumber);
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(DevEmuPd6710CardIrqLine, Pd6710CardIrqLine);
