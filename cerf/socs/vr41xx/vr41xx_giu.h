#pragma once

#include "../../peripherals/peripheral_base.h"

/* NEC VR41xx GIU (General Purpose I/O Unit): the GPIO direction/data registers plus
   the Level-2 GPIO interrupt block, whose output the ICU takes as GIUINTLREG/
   GIUINTHREG (VR4121 UM ch.19, VR4102 UM ch.18, VR4131 UM ch.14). */
class Vr41xxGiu : public Peripheral {
public:
    using Peripheral::Peripheral;

    /* GPIO(31:0) pins (VR4121 UM 19.2.1/19.2.2, VR4102 UM 18.2.1/18.2.2). */
    virtual void SetPinLevel(int pin, bool level) = 0;

    virtual bool GetPinLevel(int pin) = 0;
};
