#include "../board_detector.h"

#include "../../core/cerf_emulator.h"

namespace {

class Ipaq3650Detector : public BoardDetector {
public:
    using BoardDetector::BoardDetector;

    bool ShouldRegister() override {
        /* Kernel literal at nk.exe 0x80054850 is "H3600" (the
           H3000-platform codename shared across the H363x/365x/367x
           SKUs), not "H3650"; narrowing the needle to the SKU number
           silently makes the detector miss this ROM. */
        return RomContainsString("Compaq iPAQ H3600");
    }

    Board       GetBoard()  const override { return Board::Ipaq3650; }
    SocFamily   GetSoc()    const override { return SocFamily::SA1110; }
    const char* BoardName() const override {
        return "Compaq iPAQ H3000-platform (H3650 SKU), Intel SA-1110 StrongARM";
    }

};

}  /* namespace */

REGISTER_SERVICE_AS(Ipaq3650Detector, BoardDetector);
