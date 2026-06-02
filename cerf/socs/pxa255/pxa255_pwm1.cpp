#include "pxa255_pwm.h"

namespace {

/* PXA255 PWM channel 1 (base 0x40C00000, Table 4-46). */
class Pxa255Pwm1 : public Pxa255Pwm {
public:
    using Pxa255Pwm::Pxa255Pwm;

    uint32_t MmioBase() const override { return 0x40C00000u; }
};

}  /* namespace */

REGISTER_SERVICE(Pxa255Pwm1);
