#include "omap3530_intc.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_jit.h"
#include "../../jit/arm_cpu.h"
#include "../../jit/cpu_state.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../boards/board_detector.h"

#include <bit>
#include <cstdint>
#include <mutex>

bool Omap3530Intc::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    return bd && bd->GetSoc() == SocFamily::OMAP3530;
}

int Omap3530Intc::BankIndex(uint32_t off, uint32_t* bank_off_out) {
    for (uint32_t i = 0; i < kBankCount; ++i) {
        const uint32_t base = kBank0Base + i * kBankStride;
        if (off >= base && off < base + kBankStride) {
            *bank_off_out = off - base;
            return static_cast<int>(i);
        }
    }
    return -1;
}

int Omap3530Intc::ComputeActiveSource() const {
    int      active        = -1;
    uint32_t active_prio   = 0xFFu;
    for (uint32_t b = 0; b < kBankCount; ++b) {
        uint32_t pending = (banks_[b].itr | banks_[b].isr) & ~banks_[b].mir;
        while (pending != 0) {
            const int bit_in_bank  = std::countr_zero(pending);
            const int source       = static_cast<int>(b) * kBitsPerBank + bit_in_bank;
            const uint32_t prio    = (ilr_[source] >> 2) & 0x3Fu;
            if (prio < threshold_ &&
                (active < 0 || prio < active_prio)) {
                active      = source;
                active_prio = prio;
            }
            pending &= pending - 1u;  /* clear lowest set bit */
        }
    }
    return active;
}

bool Omap3530Intc::HasPendingUnmasked() const {
    return ComputeActiveSource() >= 0;
}

void Omap3530Intc::AssertIrq(int source_bit) {
    if (source_bit < 0 || source_bit >= static_cast<int>(kSourceCount)) {
        LOG(Caution, "Omap3530Intc::AssertIrq: source_bit %d out of "
                "range — OMAP3 has 96 IRQ sources\n", source_bit);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    bool needs_irq = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);

        /* FIQ routing not modelled — CE programs ILR[N].bit0 = 0 for
           every source. Halt loudly if a source is configured FIQ. */
        if (ilr_[source_bit] & 0x1u) {
            LOG(Caution, "Omap3530Intc::AssertIrq: source %d routed to "
                    "FIQ (ILR[%d].bit0 set) — FIQ delivery not modelled\n",
                    source_bit, source_bit);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }

        const uint32_t bank     = source_bit / kBitsPerBank;
        const uint32_t bit_mask = 1u << (source_bit % kBitsPerBank);
        banks_[bank].itr |= bit_mask;
        needs_irq = HasPendingUnmasked();
    }

    if (needs_irq) emu_.Get<ArmJit>().SetInterruptPending();
}

void Omap3530Intc::DeAssertIrq(int source_bit) {
    if (source_bit < 0 || source_bit >= static_cast<int>(kSourceCount)) {
        LOG(Caution, "Omap3530Intc::DeAssertIrq: source_bit %d out of "
                "range — OMAP3 has 96 IRQ sources\n", source_bit);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    bool still_pending = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        const uint32_t bank     = source_bit / kBitsPerBank;
        const uint32_t bit_mask = 1u << (source_bit % kBitsPerBank);
        banks_[bank].itr &= ~bit_mask;
        still_pending = HasPendingUnmasked();
    }

    /* Outside the lock so the cross-thread call to ArmJit doesn't
       nest mutex acquisition. */
    auto& jit = emu_.Get<ArmJit>();
    if (still_pending) jit.SetInterruptPending();
    else               jit.ClearInterruptPending();
}

void Omap3530Intc::AssertSubIrq(int /*main_source_bit*/, int /*sub_source_bit*/) {
    LOG(Caution, "Omap3530Intc::AssertSubIrq: OMAP3530 INTC has no "
            "sub-interrupt register layer; caller is using the wrong "
            "model for this SoC family\n");
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

void Omap3530Intc::DeliverPendingIrq() {
    bool ready = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        ready = HasPendingUnmasked();
    }
    if (!ready) return;

    auto&        jit   = emu_.Get<ArmJit>();
    ArmCpuState* state = jit.CpuState();
    if (state->cpsr.bits.irq_disable) return;

    jit.Cpu()->RaiseIrqException(state->gprs[ArmGpr::kR15]);
}

uint32_t Omap3530Intc::ReadReg(uint32_t off) {
    std::lock_guard<std::mutex> lk(state_mutex_);

    if (off >= kOffIlr0 && off < kOffIlr0 + kSourceCount * 4u) {
        return ilr_[(off - kOffIlr0) / 4u];
    }

    uint32_t bank_off = 0;
    const int bank_idx = BankIndex(off, &bank_off);
    if (bank_idx >= 0) {
        const Bank& b = banks_[bank_idx];
        switch (bank_off) {
        case kBankItr:        return b.itr;
        case kBankMir:        return b.mir;
        case kBankMirClear:   return b.mir;
        case kBankMirSet:     return b.mir;
        case kBankIsrSet:     return b.isr;
        case kBankIsrClear:   return b.isr;
        case kBankPendingIrq: return (b.itr | b.isr) & ~b.mir;
        case kBankPendingFiq: return 0;
        }
        LOG(Caution, "Omap3530Intc::ReadReg: bank %d offset 0x%X "
                "outside the documented per-bank slot set\n",
                bank_idx, bank_off);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    switch (off) {
    case kOffRevision:    return 0;
    case kOffSysConfig:   return sysconfig_;
    case kOffSysStatus:   return 0x1u;        /* RESETDONE always asserted */
    case kOffSirIrq: {
        const int active = ComputeActiveSource();
        return active >= 0 ? static_cast<uint32_t>(active) : kSpuriousSirIrq;
    }
    case kOffSirFiq:      return kSpuriousSirIrq;  /* FIQ not modelled */
    case kOffControl:     return control_;
    case kOffProtection:  return protection_;
    case kOffIdle:        return idle_;
    case kOffIrqPriority: {
        const int active = ComputeActiveSource();
        return active >= 0 ? ((ilr_[active] >> 2) & 0x3Fu) : 0xFFu;
    }
    case kOffFiqPriority: return 0xFFu;
    case kOffThreshold:   return threshold_;
    }
    LOG(Caution, "Omap3530Intc::ReadReg: offset 0x%X is outside the "
            "documented OMAP_INTC_MPU_REGS layout\n", off);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

void Omap3530Intc::WriteReg(uint32_t off, uint32_t value) {
    bool reeval_needed = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);

        if (off >= kOffIlr0 && off < kOffIlr0 + kSourceCount * 4u) {
            ilr_[(off - kOffIlr0) / 4u] = value;
            reeval_needed = true;
        } else {
            uint32_t bank_off = 0;
            const int bank_idx = BankIndex(off, &bank_off);
            if (bank_idx >= 0) {
                Bank& b = banks_[bank_idx];
                switch (bank_off) {
                case kBankItr:        /* ITR is read-only */            break;
                case kBankMir:        b.mir  = value;  reeval_needed = true; break;
                case kBankMirClear:   b.mir &= ~value; reeval_needed = true; break;
                case kBankMirSet:     b.mir |= value;  reeval_needed = true; break;
                case kBankIsrSet:     b.isr |= value;  reeval_needed = true; break;
                case kBankIsrClear:   b.isr &= ~value; reeval_needed = true; break;
                case kBankPendingIrq: /* read-only */                   break;
                case kBankPendingFiq: /* read-only */                   break;
                default:
                    LOG(Caution, "Omap3530Intc::WriteReg: bank %d "
                            "offset 0x%X outside documented slots\n",
                            bank_idx, bank_off);
                    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
                }
            } else {
                switch (off) {
                case kOffRevision:    /* read-only */         break;
                case kOffSysConfig:   sysconfig_  = value;    break;
                case kOffSysStatus:   /* status, ignored */   break;
                case kOffSirIrq:      /* read-only */         break;
                case kOffSirFiq:      /* read-only */         break;
                case kOffControl:
                    control_ = value;
                    if (value & 0x1u) reeval_needed = true;
                    break;
                case kOffProtection:  protection_ = value;    break;
                case kOffIdle:        idle_       = value;    break;
                case kOffIrqPriority: /* read-only */         break;
                case kOffFiqPriority: /* read-only */         break;
                case kOffThreshold:   threshold_ = value & 0xFFu;
                                      reeval_needed = true;
                                      break;
                default:
                    LOG(Caution, "Omap3530Intc::WriteReg: offset 0x%X "
                            "is outside the documented "
                            "OMAP_INTC_MPU_REGS layout\n", off);
                    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
                }
            }
        }
    }

    /* Outside the lock so the cross-thread call to ArmJit doesn't
       nest mutex acquisition. */
    if (reeval_needed) {
        bool pending = false;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            pending = HasPendingUnmasked();
        }
        auto& jit = emu_.Get<ArmJit>();
        if (pending) jit.SetInterruptPending();
        else         jit.ClearInterruptPending();
    }
}

namespace {

constexpr uint32_t kIntcMmioBasePa = 0x48200000u;
constexpr uint32_t kIntcMmioSize   = 0x00000400u;  /* 1 KB */

class Omap3530IntcMmio : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::OMAP3530;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kIntcMmioBasePa; }
    uint32_t MmioSize() const override { return kIntcMmioSize; }

    uint32_t ReadWord(uint32_t addr) override {
        auto& concrete = static_cast<Omap3530Intc&>(emu_.Get<IrqController>());
        const uint32_t off = addr - MmioBase();
        const uint32_t v = concrete.ReadReg(off);
        LOG(Periph, "[INTC] R off=0x%03X -> 0x%08X\n", off, v);
        return v;
    }
    void WriteWord(uint32_t addr, uint32_t value) override {
        auto& concrete = static_cast<Omap3530Intc&>(emu_.Get<IrqController>());
        const uint32_t off = addr - MmioBase();
        LOG(Periph, "[INTC] W off=0x%03X <- 0x%08X\n", off, value);
        concrete.WriteReg(off, value);
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(Omap3530Intc, IrqController);
REGISTER_SERVICE   (Omap3530IntcMmio);
