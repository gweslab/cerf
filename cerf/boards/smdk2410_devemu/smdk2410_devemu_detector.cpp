#include "../board_detector.h"

#include "../../core/cerf_emulator.h"

namespace {

/* dmatrans.dll — the DeviceEmulator's DMA host-transport driver, present on
   every DeviceEmulator BSP generation and no other board. Raw-byte scan, not
   a module-name lookup: WM6+ NB0 images keep driver names in IMGFS, which
   RomParser does not parse. */
class Smdk2410DevEmuDetector : public BoardDetector {
public:
    using BoardDetector::BoardDetector;

    bool ShouldRegister() override {
        return RomContainsString("dmatrans.dll");
    }

    Board       GetBoard()  const override { return Board::Smdk2410DevEmu; }
    SocFamily   GetSoc()    const override { return SocFamily::S3C2410; }
    const char* BoardName() const override {
        return "SMDK2410 + Microsoft DeviceEmulator BSP";
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(Smdk2410DevEmuDetector, BoardDetector);
