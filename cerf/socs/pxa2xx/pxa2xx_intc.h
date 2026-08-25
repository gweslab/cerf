#pragma once

#include "../irq_controller.h"

#include <cstdint>
#include <mutex>

class StateWriter;
class StateReader;

/* Intel PXA27x Developer's Manual 280000-001 Table 25-16: interrupt controller
   registers at 0x40D0_0000. Section 1.3: "Memory map and register locations are
   backward-compatible with the previous Intel XScale microarchitecture
   hand-held products". */
class Pxa2xxIntc : public IrqController {
public:
    using IrqController::IrqController;

    void AssertIrq   (int source_bit) override;
    void DeAssertIrq (int source_bit) override;
    void AssertSubIrq(int main_source_bit, int sub_source_bit) override;
    void DeliverPendingIrq() override;

    /* Intel PXA27x Developer's Manual 280000-001 Table 25-3: ICPR shows all
       active interrupts in the system. */
    void SetSourceLevel(uint32_t mask, uint32_t level);

    uint32_t ReadReg    (uint32_t off);
    void     WriteReg   (uint32_t off, uint32_t value);
    uint8_t  ReadByteAt (uint32_t off);
    void     WriteByteAt(uint32_t off, uint8_t value);
    bool     IsKnown    (uint32_t off) const;

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);
    void PostRestore();

protected:
    /* Intel PXA27x Developer's Manual 280000-001 Table 25-16: ICIP2, ICMR2,
       ICLR2, ICFP2 and ICPR2 at 0x9C..0xAC, ICHP at 0x18 and IPR0-39 at
       0x1C..0x98 plus 0xB0..0xCC are PXA27x additions. */
    virtual bool HasSecondBank() const = 0;

private:
    /* Intel PXA27x Developer's Manual 280000-001 Table 25-16. */
    static constexpr uint32_t kIcip     = 0x00u;
    static constexpr uint32_t kIcmr     = 0x04u;
    static constexpr uint32_t kIclr     = 0x08u;
    static constexpr uint32_t kIcfp     = 0x0Cu;
    static constexpr uint32_t kIcpr     = 0x10u;
    static constexpr uint32_t kIccr     = 0x14u;
    static constexpr uint32_t kIchp     = 0x18u;
    static constexpr uint32_t kIprLo    = 0x1Cu;
    static constexpr uint32_t kIprLoEnd = 0x98u;
    static constexpr uint32_t kIcip2    = 0x9Cu;
    static constexpr uint32_t kIcmr2    = 0xA0u;
    static constexpr uint32_t kIclr2    = 0xA4u;
    static constexpr uint32_t kIcfp2    = 0xA8u;
    static constexpr uint32_t kIcpr2    = 0xACu;
    static constexpr uint32_t kIprHi    = 0xB0u;
    static constexpr uint32_t kIprHiEnd = 0xCCu;

    /* Intel PXA27x Developer's Manual 280000-001 Table 25-13 bit 0 DIM. */
    static constexpr uint32_t kIccrMask = 0x1u;

    /* Intel PXA27x Developer's Manual 280000-001 Table 25-14: bit 31 VAL, bits
       30:6 reserved, bits 5:0 PID. */
    static constexpr uint32_t kIprMask = 0x8000003Fu;
    static constexpr uint32_t kIprVal  = 0x80000000u;
    static constexpr uint32_t kIprPid  = 0x0000003Fu;

    /* Intel PXA27x Developer's Manual 280000-001 Table 25-15: "31 R VAL_IRQ",
       "20:16 R IRQ IRQ Highest Priority Field", "15 R VAL_FIQ", "4:0 R FIQ FIQ
       Highest Priority Field". */
    static constexpr uint32_t kIchpValIrq    = 0x80000000u;
    static constexpr uint32_t kIchpIrqShift  = 16u;
    static constexpr uint32_t kIchpValFiq    = 0x00008000u;
    static constexpr uint32_t kIchpFieldMask = 0x1Fu;

    static constexpr uint32_t kBanks    = 2u;
    /* Intel PXA27x Developer's Manual 280000-001 Table 25-14: "Valid IDs: 0
       through 39". */
    static constexpr uint32_t kIprSlots = 40u;

    /* Intel PXA27x Developer's Manual 280000-001 Section 25.5.2: a bit is set
       when the corresponding peripheral has a pending unmasked IRQ interrupt;
       an interrupting source creates an IRQ if the corresponding bit in the
       ICLR is cleared. */
    uint32_t IcIpLocked(uint32_t bank) const {
        return icpr_[bank] & icmr_[bank] & ~iclr_[bank];
    }
    /* Intel PXA27x Developer's Manual 280000-001 Section 25.5.3: a bit is set if
       the corresponding peripheral has a pending unmasked FIQ interrupt waiting
       to be served. Section 25.5.5: the ICLR bit field is decoded to select
       which CPU interrupt is asserted. */
    uint32_t IcFpLocked(uint32_t bank) const {
        return icpr_[bank] & icmr_[bank] & iclr_[bank];
    }

    uint32_t IcIpAllLocked() const { return IcIpLocked(0) | IcIpLocked(1); }
    uint32_t IcFpAllLocked() const { return IcFpLocked(0) | IcFpLocked(1); }

    bool     SplitSource(int source_bit, uint32_t& bank, uint32_t& bit) const;
    uint32_t IprIndex(uint32_t off) const;
    bool     HighestPriorityLocked(uint64_t pending, uint32_t& pid) const;
    uint32_t IchpLocked();

    uint32_t ReadRegLocked (uint32_t off);
    void     WriteRegLocked(uint32_t off, uint32_t value);
    void     NotifyLocked();

    mutable std::mutex state_mtx_;

    /* Intel PXA27x Developer's Manual 280000-001 Tables 25-3, 25-9, 25-11 and
       25-13 reset columns: cleared during reset. */
    uint32_t icpr_[kBanks] = {};
    uint32_t icmr_[kBanks] = {};
    uint32_t iclr_[kBanks] = {};
    uint32_t iccr_ = 0;

    /* Intel PXA27x Developer's Manual 280000-001 Table 25-14 bit 31 VAL and
       bits 5:0 PID; Section 25.5.7: at reset these registers are marked
       invalid. */
    uint32_t ipr_[kIprSlots] = {};
};
