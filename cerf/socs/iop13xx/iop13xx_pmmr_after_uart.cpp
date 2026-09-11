#include "iop13xx_pmmr_guard.h"
namespace {
class Iop13xxPmmrAfterUart final : public Iop13xxPmmrRange<0xFFD82370u, 0x00000110u> {
public:
    using Iop13xxPmmrRange::Iop13xxPmmrRange;

};
} // namespace
REGISTER_SERVICE(Iop13xxPmmrAfterUart);
