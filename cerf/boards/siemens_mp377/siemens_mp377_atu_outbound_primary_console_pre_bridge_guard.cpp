#include "mp377_board_io_window.h"

using namespace mp377_board_io_detail;

namespace {

class SiemensMp377AtuOutboundPrimaryConsolePreBridgeGuard : public SiemensMp377AtuOutboundPrimaryGuard {
public:
    using SiemensMp377AtuOutboundPrimaryGuard::SiemensMp377AtuOutboundPrimaryGuard;
    uint32_t MmioBase() const override { return kAtuPrimaryConsoleBase; }
    uint32_t MmioSize() const override { return kSmiBridgeBase - MmioBase(); }

};

} // namespace

REGISTER_SERVICE(SiemensMp377AtuOutboundPrimaryConsolePreBridgeGuard);
