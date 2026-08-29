#include "../vr41xx/vr41xx_led_impl.h"

namespace {

using cerf_vr41xx_led_detail::Vr41xxLedBase;

/* VR4111 LED at 0x0B000240 (UM Table 24-1 p493). */
class Vr4111Led : public Vr41xxLedBase<SocFamily::VR4111, 0x0B000240u> {
public:
    using Vr41xxLedBase::Vr41xxLedBase;
};

}  /* namespace */

REGISTER_SERVICE(Vr4111Led);
