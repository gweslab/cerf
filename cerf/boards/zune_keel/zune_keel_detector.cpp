#include "../board_detector.h"

#include "../../core/cerf_emulator.h"

namespace {

class ZuneKeelDetector : public BoardDetector {
public:
    using BoardDetector::BoardDetector;

    bool ShouldRegister() override {
        return NameContains(ModuleNames(), "pyxis_keybd");
    }

    Board       GetBoard()  const override { return Board::ZuneKeel; }
    SocFamily   GetSoc()    const override { return SocFamily::iMX31; }
    const char* BoardName() const override {
        return "Microsoft Zune 30 (codename Keel), "
               "Freescale i.MX31L (ARM1136JF-S)";
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(ZuneKeelDetector, BoardDetector);
