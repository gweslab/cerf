#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "pxa255_intc.h"

#include <cstdint>

namespace {

/* PXA255 I2C controller (§9, registers at 0x40301680). No slave is modeled
   on the bus, so every master transfer completes immediately (TB → ITE/IRF):
   a driver that sets ICR.TB and polls ISR for completion must see ITE/IRF
   set or it spins forever. Interrupt-driven drivers additionally need the
   unit to drive its INTC source (IS18) while a service request is enabled
   and pending; without it WaitForSingleObject on the I2C event times out. */
class Pxa255I2c : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::PXA25x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x40300000u; }
    uint32_t MmioSize() const override { return 0x00002000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    /* §9.9 register offsets within the 0x40300000 block. */
    static constexpr uint32_t kIBMR = 0x1680u;  /* Bus Monitor (RO).      */
    static constexpr uint32_t kIDBR = 0x1688u;  /* Data Buffer.           */
    static constexpr uint32_t kICR  = 0x1690u;  /* Control.               */
    static constexpr uint32_t kISR  = 0x1698u;  /* Status.                */
    static constexpr uint32_t kISAR = 0x16A0u;  /* Slave Address.         */

    /* ICR bits (§9.9.3 Table 9-10). */
    static constexpr uint32_t kIcrUR    = 1u << 14;  /* Unit Reset.        */
    static constexpr uint32_t kIcrIRFIE = 1u << 9;   /* IRF Int Enable.    */
    static constexpr uint32_t kIcrITEIE = 1u << 8;   /* ITE Int Enable.    */
    static constexpr uint32_t kIcrTB    = 1u << 3;   /* Transfer Byte.     */
    static constexpr uint32_t kIcrStart = 1u << 0;   /* START.             */
    /* ISR bits (§9.9.4 Table 9-11). */
    static constexpr uint32_t kIsrIRF   = 1u << 7;   /* IDBR Receive Full. */
    static constexpr uint32_t kIsrITE   = 1u << 6;   /* IDBR Transmit Empty*/

    /* §4.2.5 Table 4-35 ICPR: IS18 = I2C Service Request. */
    static constexpr uint32_t kIntcI2cBit = 18u;

    void UpdateIrq();

    uint32_t icr_  = 0;        /* §9.8 reset 0.                            */
    uint32_t isr_  = 0;        /* §9.8 reset 0.                            */
    uint32_t idbr_ = 0;        /* §9.8 reset 0.                            */
    uint32_t isar_ = 0;        /* §9.8 reset 0; not affected by UR.        */
    bool     reading_ = false; /* transfer direction latched at START.     */
};

uint32_t Pxa255I2c::ReadWord(uint32_t addr) {
    switch (addr - MmioBase()) {
        case kIBMR: return 0x3u;  /* §9.9.1: SCL=1, SDA=1 — idle bus. */
        case kIDBR: return idbr_;
        case kICR:  return icr_;
        case kISR:  return isr_;
        case kISAR: return isar_;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa255I2c::WriteWord(uint32_t addr, uint32_t value) {
    switch (addr - MmioBase()) {
        case kIDBR: idbr_ = value & 0xFFu; return;
        case kISR:  isr_ &= ~value; UpdateIrq(); return;  /* §9.9.4 W1C status bits. */
        case kISAR: isar_ = value & 0x7Fu; return;
        case kICR: {
            if (value & kIcrUR) {                 /* §9.8 Unit Reset (ISAR kept). */
                icr_ = 0; isr_ = 0; idbr_ = 0; reading_ = false;
                UpdateIrq();
                return;
            }
            icr_ = value & 0xFFFFu;
            if (value & kIcrTB) {                 /* §9.9.3: initiate byte transfer. */
                if (value & kIcrStart) reading_ = (idbr_ & 1u) != 0u;  /* addr LSB = R/W. */
                if (reading_) { idbr_ = 0xFFu; isr_ |= kIsrIRF; }       /* no slave → floating. */
                else          { isr_ |= kIsrITE; }
                icr_ &= ~kIcrTB;                  /* §9.9.3: HW clears TB on completion. */
            }
            UpdateIrq();
            return;
        }
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

/* §4.2.5 IS18: the I2C unit drives its INTC source while an enabled service
   request is pending — ITE (ISR bit6) gated by ITEIE (ICR bit8), IRF (ISR
   bit7) gated by IRFIE (ICR bit9). Level-driven: the guest IST clears ITE/IRF
   via the ISR W1C to deassert. DO NOT drop this to "set ISR only" — the
   interrupt-driven bus driver (F75111 keypad init) blocks 3s/byte on
   WaitForSingleObject(I2C event) without the INTC assert. */
void Pxa255I2c::UpdateIrq() {
    const bool active =
        ((isr_ & kIsrITE) && (icr_ & kIcrITEIE)) ||
        ((isr_ & kIsrIRF) && (icr_ & kIcrIRFIE));
    if (active) emu_.Get<Pxa255Intc>().AssertSource(kIntcI2cBit);
    else        emu_.Get<Pxa255Intc>().DeassertSource(kIntcI2cBit);
}

}  /* namespace */

REGISTER_SERVICE(Pxa255I2c);
