#include "mp377_board_io_window.h"

using namespace mp377_board_io_detail;

namespace {

class SiemensMp377AtuOutboundPrimaryAfterRegsPreFbGuard : public SiemensMp377AtuOutboundPrimaryGuard {
public:
    using SiemensMp377AtuOutboundPrimaryGuard::SiemensMp377AtuOutboundPrimaryGuard;
    uint32_t MmioBase() const override { return kAtuPrimarySm501RegsEnd; }
    uint32_t MmioSize() const override { return kAtuPrimarySm501FbBase - MmioBase(); }

};

} // namespace

REGISTER_SERVICE(SiemensMp377AtuOutboundPrimaryAfterRegsPreFbGuard);
