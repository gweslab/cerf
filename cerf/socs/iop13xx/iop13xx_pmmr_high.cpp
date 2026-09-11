#include "iop13xx_pmmr_guard.h"
namespace {
class Iop13xxPmmrHigh final : public Iop13xxPmmrRange<0xFFDCD338u, 0x000B2CC8u> {
public:
    using Iop13xxPmmrRange::Iop13xxPmmrRange;

};
} // namespace
REGISTER_SERVICE(Iop13xxPmmrHigh);
