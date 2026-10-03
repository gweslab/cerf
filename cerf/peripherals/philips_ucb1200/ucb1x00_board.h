#pragma once

#include "../../core/service.h"

#include <cstdint>

/* Linux ucb1x00.h UCB_ADC_INP_TSPX .. UCB_ADC_INP_AD3: ADC_CR INP[4:2] selects
   TSPX(0) TSMX(1) TSPY(2) TSMY(3) AD0(4) AD1(5) AD2(6) AD3(7). */
class Ucb1x00Board : public Service {
public:
    using Service::Service;

    virtual uint16_t AuxAdc(uint8_t channel) = 0;

    virtual uint16_t TouchAdcX() = 0;
    virtual uint16_t TouchAdcY() = 0;
    virtual uint16_t TouchAdcPressure() = 0;

    virtual uint16_t IoInputs(uint16_t input_mask) = 0;

    virtual bool AdcExternalReference() const = 0;

    virtual bool TsCrLowBitsSetOnTouch() const = 0;
    virtual void OnIrqOutChanged(bool asserted) = 0;

    enum class SocResetReach { Never, Unknown };
    virtual SocResetReach CodecSocResetReach() const = 0;
};
