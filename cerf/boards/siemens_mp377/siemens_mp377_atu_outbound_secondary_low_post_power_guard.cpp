#include "mp377_board_io_window.h"

using namespace mp377_board_io_detail;

namespace {

class SiemensMp377AtuOutboundSecondaryLowPostPowerGuard : public Mp377BoardIoWindow {
public:
    using Mp377BoardIoWindow::Mp377BoardIoWindow;
    uint32_t MmioBase() const override { return kMp377PowerResetEnd; }
    uint32_t MmioSize() const override { return 0xD0200000u - MmioBase(); }

};

} // namespace

REGISTER_SERVICE(SiemensMp377AtuOutboundSecondaryLowPostPowerGuard);
