#pragma once

#include "sa1111_unit.h"

#include <cstdint>
#include <functional>
#include <mutex>
#include <vector>

/* SA-1111 Interrupt Controller (Developer's Manual Table 11-2, base
   0x40001600). Sub-blocks call RaiseInterrupt/LowerInterrupt with their
   Table 11-1 source number (0..63); the chip IRQ output cascades through
   an SA-1110 GPIO. */
class Sa1111Intc : public Sa1111Unit {
public:
    using Sa1111Unit::Sa1111Unit;

    bool ShouldRegister() override;

    uint32_t MmioBase() const override { return 0x40001600u; }
    uint32_t MmioSize() const override { return 0x00000200u; }

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

    /* Source 0..31 → bank 0, 32..63 → bank 1; Raise/Lower drive the raw
       input line, Raise also sets status. Lower must NOT clear status - the
       latch is edge-triggered (Dev Manual Fig 11-1), cleared only by
       INTSTATCLR W1C; clearing on Lower drops an IRQ not yet acked. */
    void RaiseInterrupt(uint8_t source);
    void LowerInterrupt(uint8_t source);

    void RegisterSampler(uint64_t sources, std::function<void()> sample);
    void SetSourceLevel(uint8_t source, bool level);

protected:
    void     OnUnitReady() override;
    void     OnChipReset(bool held) override;
    uint32_t UnitReadWord (uint32_t addr) override;
    void     UnitWriteWord(uint32_t addr, uint32_t value) override;

private:
    bool OutputAsserted() const { return (status0_ & enable0_) ||
                                         (status1_ & enable1_); }
    void DriveCascadeOutput(bool pulse_low_first);
    void SampleSources();
    void RequireUnsampled(uint32_t bank, uint32_t enable) const;
    void SetAsleep(bool asleep);
    void RequireAwake(uint8_t source) const;

    std::mutex mtx_;
    std::vector<std::function<void()>> samplers_;
    uint32_t sampled0_ = 0, sampled1_ = 0;
    bool     asleep_   = false;

    /* Latch sources whose (raw ^ pol) rose 0->1 into status; run on raw AND
       INTPOL writes - the INTPOL case is the kernel's retrigger (Fig 11-1). */
    void LatchEdges(bool bank1);

    uint32_t raw0_ = 0, raw1_ = 0;       /* IntRaw(n) per-source input lines. */
    uint32_t detect0_ = 0, detect1_ = 0; /* last (raw ^ pol) per source. */
    uint32_t inttest0_ = 0, inttest1_ = 0;
    uint32_t enable0_  = 0, enable1_  = 0;   /* INTEN0/1 */
    uint32_t polarity0_ = 0, polarity1_ = 0; /* INTPOL0/1 */
    uint32_t tstsel_   = 0;                   /* INTTSTSEL */
    uint32_t status0_  = 0, status1_  = 0;   /* INTSTATCLR0/1 */
    uint32_t wake_en0_ = 0, wake_en1_ = 0;
    uint32_t wake_pol0_ = 0, wake_pol1_ = 0;
};
