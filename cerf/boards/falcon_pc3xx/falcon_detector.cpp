#include "../board_detector.h"

#include "../../core/cerf_emulator.h"

namespace {

class FalconPc3xxDetector : public BoardDetector {
public:
    using BoardDetector::BoardDetector;

    bool ShouldRegister() override {
#if CERF_DEV_MODE
        /* xsc1bd_serial.dll = Datalogic XScale serial driver; BCDCore.dll
           = the PSC/Datalogic barcode-decoder core. Both modules are
           unique to the Falcon barcode-terminal ROM. */
        const std::string names = ModuleNames();
        return NameContains(names, "xsc1bd_serial") &&
               NameContains(names, "BCDCore");
#else
        return false;
#endif
    }

    Board       GetBoard()  const override { return Board::FalconPC3xx; }
    SocFamily   GetSoc()    const override { return SocFamily::PXA25x; }
    const char* BoardName() const override {
        return "Datalogic Falcon 4220 (PC3xx), "
               "Intel XScale PXA255 (ARMv5TE), Windows CE .NET 4.2";
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(FalconPc3xxDetector, BoardDetector);
