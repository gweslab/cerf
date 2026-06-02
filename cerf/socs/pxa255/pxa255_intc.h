#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>
#include <mutex>

/* PXA255 Interrupt Controller (manual §4.2, Table 4-50, base 0x40D00000).
   ICPR=pending, ICMR=mask, ICLR=route(0 IRQ / 1 FIQ); masked IRQ =
   ICPR&ICMR&~ICLR drives the CPU IRQ line. Public so SoC peripherals
   wire their source bit via AssertSource. */
class Pxa255Intc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x40D00000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void AssertSource(uint32_t bit_index);
    void DeassertSource(uint32_t bit_index);

private:
    /* NotifyLocked must run under this lock: a mask write racing an
       AssertSource would otherwise commit a stale SetInterruptPending and
       the guest spins in its ISR forever. */
    mutable std::mutex state_mtx_;

    uint32_t icpr_ = 0;
    uint32_t icmr_ = 0;
    uint32_t iclr_ = 0;
    uint32_t iccr_ = 0;

    uint32_t IcIpLocked() const { return icpr_ & icmr_ & ~iclr_; }
    uint32_t IcFpLocked() const { return icpr_ & icmr_ & iclr_; }

    void NotifyLocked();
    uint32_t ReadRegLocked(uint32_t off) const;
    void     WriteRegLocked(uint32_t off, uint32_t value);

    static bool IsKnown(uint32_t off) {
        return off == 0x00 || off == 0x04 || off == 0x08 ||
               off == 0x0C || off == 0x10 || off == 0x14;
    }
};
