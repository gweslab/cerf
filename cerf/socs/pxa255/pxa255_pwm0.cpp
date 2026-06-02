#include "pxa255_pwm.h"

namespace {

/* PXA255 PWM channel 0 (base 0x40B00000, Table 4-46). */
class Pxa255Pwm0 : public Pxa255Pwm {
public:
    using Pxa255Pwm::Pxa255Pwm;

    uint32_t MmioBase() const override { return 0x40B00000u; }
};

}  /* namespace */

REGISTER_SERVICE(Pxa255Pwm0);
