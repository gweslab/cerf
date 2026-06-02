#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace cerf_imx31_gpio_detail {

constexpr uint32_t kGpioSize = 0x00004000u;

/* MCIMX31RM Table 5-3. */
constexpr uint32_t kOffDr    = 0x00u;
constexpr uint32_t kOffGdir  = 0x04u;
constexpr uint32_t kOffPsr   = 0x08u;
constexpr uint32_t kOffIcr1  = 0x0Cu;
constexpr uint32_t kOffIcr2  = 0x10u;
constexpr uint32_t kOffImr   = 0x14u;
constexpr uint32_t kOffIsr   = 0x18u;

template <uint32_t kBase>
class Imx31GpioImpl : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::iMX31;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kGpioSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        switch (off) {
            case kOffDr:   return dr_;
            case kOffGdir: return gdir_;
            /* §5.3.3.3: PSR returns pad value for input pins; no external
               GPIO pins are wired into CERF, so every pin reads 0. */
            case kOffPsr:  return 0u;
            case kOffIcr1: return icr1_;
            case kOffIcr2: return icr2_;
            case kOffImr:  return imr_;
            case kOffIsr:  return isr_;
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - kBase;
        switch (off) {
            case kOffDr:   dr_   = value; return;
            case kOffGdir: gdir_ = value; return;
            case kOffIcr1: icr1_ = value; return;
            case kOffIcr2: icr2_ = value; return;
            case kOffImr:  imr_  = value; return;
            /* §5.3.3.7: ISR bits are w1c. */
            case kOffIsr:  isr_ &= ~value; return;
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

private:
    uint32_t dr_   = 0;
    uint32_t gdir_ = 0;
    uint32_t icr1_ = 0;
    uint32_t icr2_ = 0;
    uint32_t imr_  = 0;
    uint32_t isr_  = 0;
};

}  /* namespace cerf_imx31_gpio_detail */
