#pragma once

#include "../irq_controller.h"

#include <cstdint>
#include <mutex>

class StateWriter;
class StateReader;

class Omap3530Intc : public IrqController {
public:
    using IrqController::IrqController;

    bool ShouldRegister() override;

    void AssertIrq   (int source_bit)                          override;
    void AssertSubIrq(int main_source_bit, int sub_source_bit) override;
    void DeAssertIrq (int source_bit)                          override;

    uint32_t ReadReg (uint32_t offset);
    void     WriteReg(uint32_t offset, uint32_t value);

    /* Called by the sibling Omap3530IntcMmio Peripheral's SaveState/RestoreState/
       PostRestore (the registered Peripheral is stateless and delegates here). */
    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);
    void PostRestore();

private:
    /* Per-bank state. */
    struct Bank {
        uint32_t itr  = 0;                /* raw input - set by AssertIrq */
        uint32_t mir  = 0xFFFFFFFFu;      /* mask: 1 = source disabled */
        uint32_t isr  = 0;                /* software-fired bits */
    };

    template <typename F>
    static constexpr void VisitBank(Bank& b, F& field) {
        field("itr", b.itr);
        field("mir", b.mir);
        field("isr", b.isr);
    }

    /* Compute the highest-priority pending source across all banks
       (priority < threshold, not masked). Returns -1 if nothing
       pending. Caller holds state_mutex_. Ties are broken by
       lowest source number wins. */
    int ComputeActiveSource() const;

    /* True iff at least one pending source is below the threshold
       and not masked. Caller holds state_mutex_. */
    bool HasPendingUnmasked() const;

    /* Byte offsets within the MMIO range. */
    static constexpr uint32_t kSourceCount  = 96;
    static constexpr uint32_t kBankCount    = 3;
    static constexpr uint32_t kBitsPerBank  = 32;
    static constexpr uint32_t kSpuriousSirIrq = 0xFFFFFF80u;

    static constexpr uint32_t kOffRevision     = 0x000;
    static constexpr uint32_t kOffSysConfig    = 0x010;
    static constexpr uint32_t kOffSysStatus    = 0x014;
    static constexpr uint32_t kOffSirIrq       = 0x040;
    static constexpr uint32_t kOffSirFiq       = 0x044;
    static constexpr uint32_t kOffControl      = 0x048;
    static constexpr uint32_t kOffProtection   = 0x04C;
    static constexpr uint32_t kOffIdle         = 0x050;
    static constexpr uint32_t kOffIrqPriority  = 0x060;
    static constexpr uint32_t kOffFiqPriority  = 0x064;
    static constexpr uint32_t kOffThreshold    = 0x068;
    static constexpr uint32_t kBank0Base       = 0x080;
    static constexpr uint32_t kBankStride      = 0x020;
    static constexpr uint32_t kBankItr         = 0x00;
    static constexpr uint32_t kBankMir         = 0x04;
    static constexpr uint32_t kBankMirClear    = 0x08;
    static constexpr uint32_t kBankMirSet      = 0x0C;
    static constexpr uint32_t kBankIsrSet      = 0x10;
    static constexpr uint32_t kBankIsrClear    = 0x14;
    static constexpr uint32_t kBankPendingIrq  = 0x18;
    static constexpr uint32_t kBankPendingFiq  = 0x1C;
    static constexpr uint32_t kOffIlr0         = 0x100;

    /* Map an offset into the per-bank slot range to its bank index
       and bank-relative offset. Returns -1 if not in any bank's
       range. */
    static int BankIndex(uint32_t off, uint32_t* bank_off_out);

    mutable std::mutex state_mutex_;
    Bank     banks_[kBankCount]{};
    uint32_t ilr_[kSourceCount]{};
    uint32_t sysconfig_   = 0;
    uint32_t control_     = 0;
    uint32_t protection_  = 0;
    uint32_t idle_        = 0;
    uint32_t threshold_   = 0xFFu;
};
