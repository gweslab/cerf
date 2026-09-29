#include "../vr41xx/vr41xx_core_clock_impl.h"
#include "vr4121_id.h"

namespace {

/* VR4121 UM 11.2.10 p291 PClock = (18.432 MHz/CLKSP) x 64, TClock = PClock/DIVT; CLKSEL rows
   Table 1-19 p61; Count ticks with MasterOut, 1/4 of TClock (1.8). */
constexpr Vr41xxCoreClockModel kVr4121CoreClock{
    64u,
    4u,
    {{15u, 12u}, {13u, 12u}, {12u, 12u}, {10u, 16u}, {9u, 16u}, {8u, 20u}, {7u, 24u}, {0u, 0u}},
};

class Vr4121CoreClock : public Vr41xxCoreClockBase<SocId::Vr4121, kVr4121CoreClock> {
public:
    using Vr41xxCoreClockBase::Vr41xxCoreClockBase;
};

}

REGISTER_SERVICE_AS(Vr4121CoreClock, MipsCoreClock);
