#include "iop13xx_pmmr_guard.h"
namespace {
class Iop13xxPmmrAfterI2c final : public Iop13xxPmmrRange<0xFFD8251Cu, 0x00045AE4u> {
public:
    using Iop13xxPmmrRange::Iop13xxPmmrRange;

};
} // namespace
REGISTER_SERVICE(Iop13xxPmmrAfterI2c);
