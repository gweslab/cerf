#include "iop13xx_pmmr_guard.h"
namespace {
class Iop13xxPmmrAtuGap final : public Iop13xxPmmrRange<0xFFDCD100u, 0x00000200u> {
public:
    using Iop13xxPmmrRange::Iop13xxPmmrRange;

};
} // namespace
REGISTER_SERVICE(Iop13xxPmmrAtuGap);
