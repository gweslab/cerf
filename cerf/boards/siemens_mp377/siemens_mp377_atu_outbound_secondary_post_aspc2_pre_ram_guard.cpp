#include "mp377_board_io_window.h"

using namespace mp377_board_io_detail;

namespace {

class SiemensMp377AtuOutboundSecondaryPostAspc2PreRamGuard : public Mp377BoardIoWindow {
public:
    using Mp377BoardIoWindow::Mp377BoardIoWindow;
    uint32_t MmioBase() const override { return kMp377Aspc2Base + kMp377Aspc2Size; }
    uint32_t MmioSize() const override { return kMp377Aspc2RamPa - MmioBase(); }

};

} // namespace

REGISTER_SERVICE(SiemensMp377AtuOutboundSecondaryPostAspc2PreRamGuard);
