#include "../vr41xx/vr41xx_core_clock_impl.h"
#include "vr4111_id.h"

namespace {

/* VR4111 UM 11.2.8 p273 PClock = (18.432 MHz/CLKSP) x 64; CLKSEL rows Table 1-19 p57 (MasterOut
   = TClock/4 on every row); Count ticks with MasterOut at 1/8, 1/12 or 1/16 of PClock (1.8 p56). */
constexpr Vr41xxCoreClockModel kVr4111CoreClock{
    64u,
    4u,
    {{24u, 8u}, {19u, 12u}, {18u, 12u}, {17u, 12u}, {15u, 12u}, {14u, 12u}, {13u, 16u}, {12u, 16u}},
};

class Vr4111CoreClock : public Vr41xxCoreClockBase<SocId::Vr4111, kVr4111CoreClock> {
public:
    using Vr41xxCoreClockBase::Vr41xxCoreClockBase;
};

}

REGISTER_SERVICE_AS(Vr4111CoreClock, MipsCoreClock);
