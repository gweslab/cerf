#include "mp377_board_io_window.h"

using namespace mp377_board_io_detail;

namespace {

class SiemensMp377FfBandLowGuard : public Mp377BoardIoWindow {
public:
    using Mp377BoardIoWindow::Mp377BoardIoWindow;
    uint32_t MmioBase() const override { return 0xFF000000u; }
    uint32_t MmioSize() const override { return 0x00D80000u; }

};

} // namespace

REGISTER_SERVICE(SiemensMp377FfBandLowGuard);
