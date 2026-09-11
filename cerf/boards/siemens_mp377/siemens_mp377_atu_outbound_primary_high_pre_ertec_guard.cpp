#include "mp377_board_io_window.h"

using namespace mp377_board_io_detail;

namespace {

class SiemensMp377AtuOutboundPrimaryHighPreErtecGuard : public SiemensMp377AtuOutboundPrimaryGuard {
public:
    using SiemensMp377AtuOutboundPrimaryGuard::SiemensMp377AtuOutboundPrimaryGuard;
    uint32_t MmioBase() const override { return kSmiBridgeEnd; }
    uint32_t MmioSize() const override { return siemens_mp377::kErtecSmallBarsBase - MmioBase(); }

};

} // namespace

REGISTER_SERVICE(SiemensMp377AtuOutboundPrimaryHighPreErtecGuard);
