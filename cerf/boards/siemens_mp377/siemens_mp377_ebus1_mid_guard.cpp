#include "mp377_board_io_window.h"

using namespace mp377_board_io_detail;

namespace {

class SiemensMp377Ebus1MidGuard : public Mp377BoardIoWindow {
public:
    using Mp377BoardIoWindow::Mp377BoardIoWindow;
    uint32_t MmioBase() const override { return siemens_mp377::kDebugLedProgressEnd; }
    uint32_t MmioSize() const override { return siemens_mp377::kDebugLedTickBase - MmioBase(); }

};

} // namespace

REGISTER_SERVICE(SiemensMp377Ebus1MidGuard);
