#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>
#include <mutex>

class Imx31Avic : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x68000000u; }
    uint32_t MmioSize() const override { return 0x00004000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void AssertSource(uint32_t source_num);
    void DeassertSource(uint32_t source_num);

private:
    mutable std::mutex state_mtx_;

    uint64_t src_hw_    = 0;
    uint32_t intcntl_   = 0;
    /* MCIMX31RM Figure 9-4 / Table 9-5: NIMASK resets to 0x1F. Per the
       encoding a value >=16 disables no interrupts; 0 would disable all
       priority-0 sources. The kernel leaves NIMASK at reset, so a wrong
       reset of 0 masks the priority-0 EPIT tick and the scheduler stalls. */
    uint32_t nimask_    = 0x1Fu;
    uint64_t intenable_ = 0;
    uint64_t inttype_   = 0;
    uint64_t intfrc_    = 0;
    uint32_t niprio_[8] = {};
    uint32_t vector_[64]= {};

    uint64_t Intsrc() const { return src_hw_ | intfrc_; }
    uint64_t Nipnd () const { return Intsrc() & intenable_ & ~inttype_; }
    uint64_t Fipnd () const { return Intsrc() & intenable_ &  inttype_; }
    bool     IrqActiveLocked() const;
    bool     FiqActiveLocked() const;

    void NotifyLocked();

    uint32_t ReadRegLocked (uint32_t off) const;
    void     WriteRegLocked(uint32_t off, uint32_t value);

    /* Table 9-18 NIVECSR / FIVECSR word: (source<<16)|priority for the
       highest-priority source in `pending`, or 0xFFFFFFFF if none. */
    uint32_t VecsrLocked(uint64_t pending) const;

    static bool IsKnownOffset(uint32_t off) {
        if (off <= 0x64u && (off & 0x3u) == 0u) return true;
        if (off >= 0x100u && off <= 0x1FCu && (off & 0x3u) == 0u) return true;
        return false;
    }
};
