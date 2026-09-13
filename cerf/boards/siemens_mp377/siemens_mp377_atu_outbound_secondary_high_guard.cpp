#include "mp377_board_io_window.h"

using namespace mp377_board_io_detail;

namespace {

class SiemensMp377AtuOutboundSecondaryHighGuard : public Mp377BoardIoWindow {
public:
    using Mp377BoardIoWindow::Mp377BoardIoWindow;
    uint32_t MmioBase() const override { return 0xD0280000u; }
    uint32_t MmioSize() const override { return 0x03D80000u; }

};

} // namespace

REGISTER_SERVICE(SiemensMp377AtuOutboundSecondaryHighGuard);
