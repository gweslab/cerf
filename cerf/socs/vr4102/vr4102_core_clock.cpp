#include "../vr41xx/vr41xx_core_clock_impl.h"
#include "vr4102_id.h"

namespace {

/* VR4102 UM 10.2.8 p245 PClock = (18.432 MHz/CLKSP) x 32, TClock = x 16; CLKSEL rows Table 2-5
   p67; MasterOut = PClock/4 (1.8 p53), Count ticks with MasterOut (6.3.3 p161). */
constexpr Vr41xxCoreClockModel kVr4102CoreClock{
    32u,
    2u,
    {{18u, 4u}, {16u, 4u}, {14u, 4u}, {13u, 4u}, {12u, 4u}, {11u, 4u}, {0u, 0u}, {0u, 0u}},
};

class Vr4102CoreClock : public Vr41xxCoreClockBase<SocId::Vr4102, kVr4102CoreClock> {
public:
    using Vr41xxCoreClockBase::Vr41xxCoreClockBase;
};

}

REGISTER_SERVICE_AS(Vr4102CoreClock, MipsCoreClock);
