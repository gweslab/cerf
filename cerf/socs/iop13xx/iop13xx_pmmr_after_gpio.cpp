#include "iop13xx_pmmr_guard.h"
namespace {
class Iop13xxPmmrAfterGpio final : public Iop13xxPmmrRange<0xFFD8248Cu, 0x00000074u> {
public:
    using Iop13xxPmmrRange::Iop13xxPmmrRange;

};
} // namespace
REGISTER_SERVICE(Iop13xxPmmrAfterGpio);
