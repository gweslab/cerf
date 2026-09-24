#include "../irq_controller.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm/arm_jit.h"
#include "../../jit/arm/arm_cpu.h"
#include "../../jit/arm/arm_mmu.h"
#include "../../jit/arm/cpu_state.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../boards/board_context.h"
#include "s3c2410_id.h"
#include "../../state/state_stream.h"
#include "s3c2410_eint_source.h"
#include "s3c2410_sub_source_levels.h"

#include <bit>
#include <mutex>

namespace {

class S3C2410Intc : public IrqController {
public:
    using IrqController::IrqController;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::S3c2410;
    }

    /* IrqController API. */
    void AssertIrq   (int source_bit) override;
    void AssertSubIrq(int main_source_bit, int sub_source_bit) override;

    /* MMIO surface - called by the sibling S3C2410IntcMmio Peripheral
       (same TU; static_cast from IrqController& is safe). */
    uint32_t ReadReg (uint32_t offset);
    void     WriteReg(uint32_t offset, uint32_t value);

    /* State image: the 8 register slots are the whole INTC state
       (INTPND/INTOFFSET are recomputed from SRCPND/INTMSK but stored). */
    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);
    void PostRestore();

private:
    static constexpr size_t   kSlotCount       = 8;
    static constexpr uint32_t kSlotSRCPND      = 0;
    static constexpr uint32_t kSlotINTMOD      = 1;
    static constexpr uint32_t kSlotINTMSK      = 2;
    static constexpr uint32_t kSlotPRIORITY    = 3;
    static constexpr uint32_t kSlotINTPND      = 4;
    static constexpr uint32_t kSlotINTOFFSET   = 5;
    static constexpr uint32_t kSlotSUBSRCPND   = 6;
    static constexpr uint32_t kSlotINTSUBMSK   = 7;

    /* Recompute INTPND + INTOFFSET from current SRCPND + INTMSK.
       Default priority config: lowest-numbered pending bit wins.
       Caller holds state_mutex_. */
    void RecomputeIntpndIntoffset();

    /* UM printed 14-17 SUBSRCPND [10] INT_ADC, [9] INT_TC, [8:6] UART2, [5:3]
       UART1, [2:0] UART0; printed 14-3 groups INT_ADC as "ADC EOC and Touch
       interrupt (INT_ADC/INT_TC)"; printed 14-7 SRCPND INT_ADC [31],
       INT_UART0 [28], INT_UART1 [23], INT_UART2 [15]. */
    struct SubGroup { uint32_t sub_mask; int main_bit; };
    static constexpr SubGroup kSubGroups[] = {
        {0x007u, 28}, {0x038u, 23}, {0x1C0u, 15}, {0x600u, 31},
    };

    int      MainSourceForSubLocked(int sub_source_bit) const;
    uint32_t SubSourceRollupLocked() const;
    void     ApplySubSourceRollupLocked();

    /* True iff (SRCPND & ~INTMSK) is non-zero. Caller holds
       state_mutex_. */
    bool HasPendingUnmasked() const;

    std::mutex state_mutex_;
    /* INTMSK powers up to 0xFFFFFFFF (everything masked) per the
       chip; the kernel's OAL clears bits as it brings sources online.
       Other slots reset to zero. */
    uint32_t storage_[kSlotCount] = {
        /* SRCPND    */ 0,
        /* INTMOD    */ 0,
        /* INTMSK    */ 0xFFFFFFFFu,
        /* PRIORITY  */ 0x0000007Fu,  /* reset value per S3C2410 UM */
        /* INTPND    */ 0,
        /* INTOFFSET */ 0,
        /* SUBSRCPND */ 0,
        /* INTSUBMSK */ 0x000007FFu,  /* reset value per S3C2410 UM */
    };
};

void S3C2410Intc::RecomputeIntpndIntoffset() {
    const uint32_t srcpnd  = storage_[kSlotSRCPND];
    const uint32_t intmsk  = storage_[kSlotINTMSK];
    const uint32_t pending = srcpnd & ~intmsk;
    if (pending == 0) {
        storage_[kSlotINTPND]    = 0;
        storage_[kSlotINTOFFSET] = 0;
        return;
    }
    /* Default priority config: lowest source bit number wins. The
       chip's full priority arbiter (rotation enabled per ARB) is
       not modelled - CE leaves PRIORITY at the reset value. */
    const int bit = std::countr_zero(pending);
    storage_[kSlotINTPND]    = (1u << bit);
    storage_[kSlotINTOFFSET] = static_cast<uint32_t>(bit);
}

int S3C2410Intc::MainSourceForSubLocked(int sub_source_bit) const {
    for (const SubGroup& g : kSubGroups)
        if (g.sub_mask & (1u << sub_source_bit)) return g.main_bit;
    return -1;
}

uint32_t S3C2410Intc::SubSourceRollupLocked() const {
    const uint32_t active =
        storage_[kSlotSUBSRCPND] & ~storage_[kSlotINTSUBMSK];
    uint32_t main_pending = 0;
    for (const SubGroup& g : kSubGroups)
        if (active & g.sub_mask) main_pending |= 1u << g.main_bit;
    return main_pending;
}

void S3C2410Intc::ApplySubSourceRollupLocked() {
    storage_[kSlotSRCPND] |= SubSourceRollupLocked();
    RecomputeIntpndIntoffset();
}

bool S3C2410Intc::HasPendingUnmasked() const {
    return (storage_[kSlotSRCPND] & ~storage_[kSlotINTMSK]) != 0;
}

void S3C2410Intc::AssertIrq(int source_bit) {
    if (source_bit < 0 || source_bit >= 32) {
        LOG(Caution, "S3C2410Intc::AssertIrq: source_bit %d out of "
                "range - main SRCPND is 32 bits per S3C2410 UM\n",
                source_bit);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        const uint32_t bit_mask = 1u << source_bit;

        if (storage_[kSlotINTMOD] & bit_mask) {
            LOG(Caution, "S3C2410Intc::AssertIrq: source %d configured "
                    "as FIQ (INTMOD bit set) - FIQ routing not "
                    "modelled\n", source_bit);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }

        storage_[kSlotSRCPND] |= bit_mask;
        RecomputeIntpndIntoffset();
        if (HasPendingUnmasked()) emu_.Get<ArmJit>().SetInterruptPending();
    }
}

void S3C2410Intc::AssertSubIrq(int main_source_bit, int sub_source_bit) {
    /* S3C2410A User Manual ch.14, INTSUBMSK p.14-18: bits [10:0] =
       INT_ADC/TC/ERR2/TXD2/RXD2/ERR1/TXD1/RXD1/ERR0/TXD0/RXD0,
       Reserved [31:11]. */
    if (sub_source_bit < 0 || sub_source_bit >= 11) {
        LOG(Caution, "S3C2410Intc::AssertSubIrq: sub_source_bit %d out "
                "of range - SUBSRCPND has 11 bits per S3C2410 UM\n",
                sub_source_bit);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    if (main_source_bit < 0 || main_source_bit >= 32) {
        LOG(Caution, "S3C2410Intc::AssertSubIrq: main_source_bit %d "
                "out of range\n", main_source_bit);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        const uint32_t sub_mask  = 1u << sub_source_bit;
        const uint32_t main_mask = 1u << main_source_bit;

        if (storage_[kSlotINTMOD] & main_mask) {
            LOG(Caution, "S3C2410Intc::AssertSubIrq: main source %d "
                    "configured as FIQ (INTMOD bit set) - FIQ routing "
                    "not modelled\n", main_source_bit);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }

        if (MainSourceForSubLocked(sub_source_bit) != main_source_bit) {
            LOG(Caution, "S3C2410Intc::AssertSubIrq: sub source %d belongs to "
                    "main source %d, caller passed %d\n", sub_source_bit,
                    MainSourceForSubLocked(sub_source_bit), main_source_bit);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }

        /* Sub-pending stays latched even when INTSUBMSK masks it -
           drivers read SUBSRCPND directly to demux sub-IRQs. */
        storage_[kSlotSUBSRCPND] |= sub_mask;

        ApplySubSourceRollupLocked();
        if (HasPendingUnmasked()) emu_.Get<ArmJit>().SetInterruptPending();
    }
}

uint32_t S3C2410Intc::ReadReg(uint32_t offset) {
    const uint32_t slot = offset / 4u;
    if (slot >= kSlotCount) {
        LOG(Caution, "S3C2410Intc::ReadReg: offset 0x%X out of range\n",
                offset);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    uint32_t value;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        value = storage_[slot];
    }
    return value;
}

void S3C2410Intc::WriteReg(uint32_t offset, uint32_t value) {
    const uint32_t slot = offset / 4u;
    if (slot >= kSlotCount) {
        LOG(Caution, "S3C2410Intc::WriteReg: offset 0x%X out of range\n",
                offset);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    uint32_t cleared_sub  = 0;
    uint32_t cleared_main = 0;

    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        switch (slot) {
            case kSlotSUBSRCPND:
                cleared_sub = storage_[slot] & value;
                storage_[slot] &= ~value;
                ApplySubSourceRollupLocked();
                break;

            case kSlotSRCPND:
                /* W1C - bit set in `value` clears that bit. The kernel's
                   IRQ handler exit sequence writes 1s to clear pending
                   bits before IRETing. */
                cleared_main = storage_[slot] & value;
                storage_[slot] &= ~value;
                ApplySubSourceRollupLocked();
                break;

            case kSlotINTPND:
                storage_[slot] &= ~value;
                RecomputeIntpndIntoffset();
                break;

            case kSlotINTSUBMSK:
                storage_[slot] = value;
                ApplySubSourceRollupLocked();
                break;

            case kSlotINTMSK:
                storage_[slot] = value;
                RecomputeIntpndIntoffset();
                break;

            case kSlotINTOFFSET:
                /* Read-only on the chip - drop writes. */
                break;

            case kSlotINTMOD:
            case kSlotPRIORITY:
                storage_[slot] = value;
                break;

            default:
                /* unreachable - slot bounds-checked above */
                break;
        }
        auto& jit = emu_.Get<ArmJit>();
        if (HasPendingUnmasked()) jit.SetInterruptPending();
        else                      jit.ClearInterruptPending();
    }

    emu_.Get<S3C2410SubSourceLevels>().ReassertStillHeld(cleared_sub);
    if (cleared_main != 0u) {
        emu_.Get<S3C2410EintSource>().ReassertHeldLevelEints(cleared_main);
    }
}

void S3C2410Intc::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    w.WriteBytes("storage", storage_, sizeof(storage_));
}

void S3C2410Intc::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    r.ReadBytes("storage", storage_, sizeof(storage_));
}

void S3C2410Intc::PostRestore() {
    /* Re-derive the JIT IRQ-pending latch from the restored SRCPND/INTMSK after
       every peripheral's RestoreState has run - the INTC owns the CPU IRQ line. */
    std::lock_guard<std::mutex> lk(state_mutex_);
    ApplySubSourceRollupLocked();
    auto& jit = emu_.Get<ArmJit>();
    if (HasPendingUnmasked()) jit.SetInterruptPending();
    else                      jit.ClearInterruptPending();
}

class S3C2410IntcMmio : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::S3c2410;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x4A000000u; }
    uint32_t MmioSize() const override { return 0x00100000u; }

    uint32_t ReadWord(uint32_t addr) override {
        auto& concrete = static_cast<S3C2410Intc&>(emu_.Get<IrqController>());
        return concrete.ReadReg(addr - MmioBase());
    }
    void WriteWord(uint32_t addr, uint32_t value) override {
        auto& concrete = static_cast<S3C2410Intc&>(emu_.Get<IrqController>());
        concrete.WriteReg(addr - MmioBase(), value);
    }

    void SaveState(StateWriter& w) override {
        static_cast<S3C2410Intc&>(emu_.Get<IrqController>()).SaveState(w);
    }
    void RestoreState(StateReader& r) override {
        static_cast<S3C2410Intc&>(emu_.Get<IrqController>()).RestoreState(r);
    }
    void PostRestore() override {
        static_cast<S3C2410Intc&>(emu_.Get<IrqController>()).PostRestore();
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(S3C2410Intc,    IrqController);
REGISTER_SERVICE   (S3C2410IntcMmio);
