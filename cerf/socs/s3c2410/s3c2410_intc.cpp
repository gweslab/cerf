#include "../irq_controller.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_jit.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/cpu_state.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../boards/board_detector.h"

#include <bit>
#include <mutex>

namespace {

class S3C2410Intc : public IrqController {
public:
    using IrqController::IrqController;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::S3C2410;
    }

    /* IrqController API. */
    void AssertIrq   (int source_bit) override;
    void AssertSubIrq(int main_source_bit, int sub_source_bit) override;
    void DeliverPendingIrq() override;

    /* MMIO surface — called by the sibling S3C2410IntcMmio Peripheral
       (same TU; static_cast from IrqController& is safe). */
    uint32_t ReadReg (uint32_t offset);
    void     WriteReg(uint32_t offset, uint32_t value);

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
       not modelled — CE leaves PRIORITY at the reset value. */
    const int bit = std::countr_zero(pending);
    storage_[kSlotINTPND]    = (1u << bit);
    storage_[kSlotINTOFFSET] = static_cast<uint32_t>(bit);
}

bool S3C2410Intc::HasPendingUnmasked() const {
    return (storage_[kSlotSRCPND] & ~storage_[kSlotINTMSK]) != 0;
}

void S3C2410Intc::AssertIrq(int source_bit) {
    if (source_bit < 0 || source_bit >= 32) {
        LOG(Caution, "S3C2410Intc::AssertIrq: source_bit %d out of "
                "range — main SRCPND is 32 bits per S3C2410 UM\n",
                source_bit);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    bool needs_irq = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        const uint32_t bit_mask = 1u << source_bit;

        /* FIQ is not modelled — fail loud rather than silently dropping
           the assertion or routing it to the IRQ vector incorrectly. */
        if (storage_[kSlotINTMOD] & bit_mask) {
            LOG(Caution, "S3C2410Intc::AssertIrq: source %d configured "
                    "as FIQ (INTMOD bit set) — FIQ routing not "
                    "modelled\n", source_bit);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }

        storage_[kSlotSRCPND] |= bit_mask;
        RecomputeIntpndIntoffset();
        needs_irq = HasPendingUnmasked();
    }

    if (needs_irq) emu_.Get<ArmJit>().SetInterruptPending();
}

void S3C2410Intc::AssertSubIrq(int main_source_bit, int sub_source_bit) {
    /* SUBSRCPND has 11 bits (INT_RXD0/TXD0/ERR0/RXD1/TXD1/ERR1/RXD2/
       TXD2/ERR2/TC/ADC at bits 0..10) per the BSP's
       SubInterruptCollection bitfield union in dev_emu's devices.h. */
    if (sub_source_bit < 0 || sub_source_bit >= 11) {
        LOG(Caution, "S3C2410Intc::AssertSubIrq: sub_source_bit %d out "
                "of range — SUBSRCPND has 11 bits per S3C2410 UM\n",
                sub_source_bit);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    if (main_source_bit < 0 || main_source_bit >= 32) {
        LOG(Caution, "S3C2410Intc::AssertSubIrq: main_source_bit %d "
                "out of range\n", main_source_bit);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    bool needs_irq = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        const uint32_t sub_mask  = 1u << sub_source_bit;
        const uint32_t main_mask = 1u << main_source_bit;

        if (storage_[kSlotINTMOD] & main_mask) {
            LOG(Caution, "S3C2410Intc::AssertSubIrq: main source %d "
                    "configured as FIQ (INTMOD bit set) — FIQ routing "
                    "not modelled\n", main_source_bit);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }

        /* Sub-pending stays latched even when INTSUBMSK masks it —
           drivers read SUBSRCPND directly to demux sub-IRQs. */
        storage_[kSlotSUBSRCPND] |= sub_mask;

        /* Sub→main rollup gates through INTSUBMSK (combinational OR on
           real silicon); SRCPND and SUBSRCPND latch independently so
           drivers W1C both at ack. */
        if ((storage_[kSlotINTSUBMSK] & sub_mask) == 0) {
            storage_[kSlotSRCPND] |= main_mask;
            RecomputeIntpndIntoffset();
            needs_irq = HasPendingUnmasked();
        }
    }

    if (needs_irq) emu_.Get<ArmJit>().SetInterruptPending();
}

void S3C2410Intc::DeliverPendingIrq() {
    bool ready = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        ready = HasPendingUnmasked();
    }
    if (!ready) return;

    auto&        jit   = emu_.Get<ArmJit>();
    ArmCpuState* state = jit.CpuState();
    if (state->cpsr.bits.irq_disable) return;

    /* Faulting PC is the next-instruction PC at this between-blocks
       observation point; ArmCpu::RaiseIrqException applies the
       per-spec +4 itself. The pending bit stays set — kernel ack via
       INTPND W1C clears it through WriteReg's ClearInterruptPending. */
    jit.Cpu()->RaiseIrqException(state->gprs[ArmGpr::kR15]);
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

    bool needs_halt = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        switch (slot) {
            case kSlotSRCPND:
            case kSlotINTPND:
            case kSlotSUBSRCPND:
                /* W1C — bit set in `value` clears that bit. The kernel's
                   IRQ handler exit sequence writes 1s to clear pending
                   bits before IRETing. */
                storage_[slot] &= ~value;
                RecomputeIntpndIntoffset();
                needs_halt = HasPendingUnmasked();
                break;

            case kSlotINTMSK:
            case kSlotINTSUBMSK:
                storage_[slot] = value;
                RecomputeIntpndIntoffset();
                needs_halt = HasPendingUnmasked();
                break;

            case kSlotINTOFFSET:
                /* Read-only on the chip — drop writes. */
                break;

            case kSlotINTMOD:
            case kSlotPRIORITY:
                storage_[slot] = value;
                break;

            default:
                /* unreachable — slot bounds-checked above */
                break;
        }
    }

    /* Mirror JIT pending against post-W1C state — when the last
       unmasked source drains, the trampoline must re-arm to no-deliver. */
    auto& jit = emu_.Get<ArmJit>();
    if (needs_halt) jit.SetInterruptPending();
    else            jit.ClearInterruptPending();
}

class S3C2410IntcMmio : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::S3C2410;
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
};

}  /* namespace */

REGISTER_SERVICE_AS(S3C2410Intc,    IrqController);
REGISTER_SERVICE   (S3C2410IntcMmio);
