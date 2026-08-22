#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../irq_controller.h"

#include <cstdint>

namespace {

/* Intel PXA27x Developer's Manual 280000-001 Table 9-13 (page 9-31) "Standard
   I2C Register Summary": "0x4030_1680 IBMR", "0x4030_1688 IDBR", "0x4030_1690
   ICR", "0x4030_1698 ISR", "0x4030_16A0 ISAR". */
class Pxa27xI2c : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA27x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x40300000u; }
    uint32_t MmioSize() const override { return 0x00002000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    static constexpr uint32_t kIBMR = 0x1680u;
    static constexpr uint32_t kIDBR = 0x1688u;
    static constexpr uint32_t kICR  = 0x1690u;
    static constexpr uint32_t kISR  = 0x1698u;
    static constexpr uint32_t kISAR = 0x16A0u;

    /* MK500 OAL guest 0x801BB188 "MOV r0, #0x400000; ORR r0, r0, #0x3000; MOV
       r1, #0x2C" maps PA 0x4030_0000 for 0x2C bytes; MK500 I2C driver guest
       0x801BD7DC "MOV r2, #0x4000; STR r2, [r3, #0x10]" writes ICR[UR] at +0x10
       of that mapping, and guest 0x801BD7E4 reads ISR at +0x18. */
    static constexpr uint32_t kAliasWindow = 0x2Cu;

    static uint32_t Normalize(uint32_t off) {
        return off < kAliasWindow ? off + kIBMR : off;
    }

    /* Table 9-8 (page 9-23) header row, bit 31 down to bit 0: "reserved", "FM",
       "UR", "SADIE", "ALDIE", "SSDIE", "BEIE", "DRFIE", "ITEIE", "GCD", "IUE",
       "SCLE", "MA", "TB", "ACKNAK", "STOP", "START"; "31:16 reserved"; the Reset
       row reads 0 for bits 15:0. */
    static constexpr uint32_t kIcrMask  = 0x0000FFFFu;

    /* Table 9-8 (page 9-23): "14 R/W UR Unit Reset ... 1 = Reset the I2C
       interface only." */
    static constexpr uint32_t kIcrUR    = 0x00004000u;

    /* Table 9-8 (page 9-24): "9 R/W DRFIE DBR Receive Full Interrupt Enable",
       "8 R/W ITEIE IDBR Transmit Empty Interrupt Enable". */
    static constexpr uint32_t kIcrDRFIE = 0x00000200u;
    static constexpr uint32_t kIcrITEIE = 0x00000100u;

    /* Table 9-8 (page 9-25): "3 R/W TB Transfer Byte ... 0 = Cleared by I2C
       interface when the byte is sent/received. 1 = Send/receive a byte." */
    static constexpr uint32_t kIcrTB    = 0x00000008u;
    static constexpr uint32_t kIcrStop  = 0x00000002u;
    static constexpr uint32_t kIcrStart = 0x00000001u;

    /* Table 9-9 (pages 9-27, 9-28): "31:11 reserved", "10 Read Clear BED", "9
       Read Clear SAD", "8 Read Clear GCAD", "7 Read Clear IRF", "6 Read Clear
       ITE", "5 Read Clear ALD", "4 Read Clear SSD", "3 R IBB", "2 R UB", "1 R
       ACKNAK", "0 R RWM"; the Reset row reads 0 for bits 10:0. */
    static constexpr uint32_t kIsrWriteClear = 0x000007F0u;
    static constexpr uint32_t kIsrIRF        = 0x00000080u;
    static constexpr uint32_t kIsrITE        = 0x00000040u;
    static constexpr uint32_t kIsrRWM        = 0x00000001u;

    /* Table 9-12 (page 9-30) IBMR: "1 R SCL", "0 R SDA"; the Reset row reads 1
       for both. */
    static constexpr uint32_t kIbmrIdle = 0x00000003u;

    /* Table 25-2 (page 25-5) "Bit Positions for Primary Interrupt Sources":
       "IP[18] I2C I2C service request 18". */
    static constexpr int kIntcI2c = 18;

    void UpdateIrq();

    uint32_t icr_  = 0;
    uint32_t isr_  = 0;
    /* Table 9-11 (page 9-30) IDBR Reset row: 0. */
    uint32_t idbr_ = 0;
    /* Section 9.5.3 (page 9-28): "If the processor is reset, the ISAR is not
       affected. The ISAR register default value is 00000002." */
    uint32_t isar_ = 0x00000002u;
    bool     reading_ = false;
};

uint32_t Pxa27xI2c::ReadWord(uint32_t addr) {
    switch (Normalize(addr - MmioBase())) {
        case kIBMR: return kIbmrIdle;
        case kIDBR: return idbr_;
        case kICR:  return icr_;
        /* Table 9-9 (page 9-28): "0 R RWM Read/Write Mode 0 = The I2C interface
           is in master-transmit or slave-receive mode. 1 = The I2C interface is
           in master-receive or slave-transmit mode." */
        case kISR:  return isr_ | (reading_ ? kIsrRWM : 0u);
        case kISAR: return isar_;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa27xI2c::WriteWord(uint32_t addr, uint32_t value) {
    switch (Normalize(addr - MmioBase())) {
        /* Table 9-11 (page 9-30): "7:0 R/W Data Buffer". */
        case kIDBR: idbr_ = value & 0xFFu; return;
        case kISR:  isr_ &= ~(value & kIsrWriteClear); UpdateIrq(); return;
        /* Table 9-10 (page 9-29): "31:07 reserved", "6:0 R/W Slave Address". */
        case kISAR: isar_ = value & 0x7Fu; return;
        case kICR: {
            /* Section 9.5.3 (page 9-28): "If the processor is reset, the ISAR is
               not affected." */
            if (value & kIcrUR) {
                icr_ = 0;
                isr_ = 0;
                idbr_ = 0;
                reading_ = false;
                UpdateIrq();
                return;
            }
            icr_ = value & kIcrMask;
            if (value & kIcrTB) {
                /* Table 9-9 (page 9-28): RWM "is the R/nW bit of the slave
                   address." */
                if (value & kIcrStart) reading_ = (idbr_ & 1u) != 0u;
                if (reading_) {
                    idbr_ = 0xFFu;
                    isr_ |= kIsrIRF;
                } else {
                    isr_ |= kIsrITE;
                }
                icr_ &= ~kIcrTB;
            }
            /* Table 9-9 (page 9-28): RWM "is automatically cleared by hardware
               after a STOP state." */
            if (value & kIcrStop) reading_ = false;
            UpdateIrq();
            return;
        }
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

/* Section 9.5.2 (page 9-26): "The ISR signals I2C interrupts to the PXA27x
   processor interrupt controller." "The ISR also clears the following
   interrupts signaled from the I2C interface: IDBR receive full, IDBR transmit
   empty". */
void Pxa27xI2c::UpdateIrq() {
    const bool active = ((isr_ & kIsrITE) && (icr_ & kIcrITEIE)) ||
                        ((isr_ & kIsrIRF) && (icr_ & kIcrDRFIE));
    auto& intc = emu_.Get<IrqController>();
    if (active) intc.AssertIrq  (kIntcI2c);
    else        intc.DeAssertIrq(kIntcI2c);
}

void Pxa27xI2c::SaveState(StateWriter& w) {
    w.Write(icr_); w.Write(isr_); w.Write(idbr_); w.Write(isar_);
    w.Write(reading_);
}

void Pxa27xI2c::RestoreState(StateReader& r) {
    r.Read(icr_); r.Read(isr_); r.Read(idbr_); r.Read(isar_);
    r.Read(reading_);
}

}  /* namespace */

REGISTER_SERVICE(Pxa27xI2c);
