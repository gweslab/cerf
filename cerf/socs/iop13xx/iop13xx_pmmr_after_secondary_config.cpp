#include "iop13xx_pmmr_guard.h"
namespace {
class Iop13xxPmmrAfterSecondaryConfig final : public Iop13xxPmmrRange<0xFFDC8334u, 0x00004CCCu> {
public:
    using Iop13xxPmmrRange::Iop13xxPmmrRange;

};
} // namespace
REGISTER_SERVICE(Iop13xxPmmrAfterSecondaryConfig);
