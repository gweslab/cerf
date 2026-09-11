#include "iop13xx_pmmr_guard.h"
namespace {
class Iop13xxPmmrAfterSecondaryStatus final : public Iop13xxPmmrRange<0xFFDC8010u, 0x0000031Cu> {
public:
    using Iop13xxPmmrRange::Iop13xxPmmrRange;

};
} // namespace
REGISTER_SERVICE(Iop13xxPmmrAfterSecondaryStatus);
