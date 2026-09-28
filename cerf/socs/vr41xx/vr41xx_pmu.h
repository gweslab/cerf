#pragma once

#include "../../peripherals/peripheral_base.h"

class Vr41xxPmu : public Peripheral {
public:
    using Peripheral::Peripheral;

    virtual void OnGpioLevel(int pin, bool prev, bool level) = 0;
    virtual void LatchRtcAlarmWake() = 0;
};
