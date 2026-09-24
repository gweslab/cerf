#include "imx51_tzic.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm/arm_jit.h"
#include "../../jit/arm/arm_cpu.h"
#include "../../jit/arm/cpu_state.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../../boards/board_context.h"
#include "imx51_id.h"

#include <bit>
#include <cstdint>
#include <mutex>

bool Imx51Tzic::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Imx51;
}

bool Imx51Tzic::SourceDeliverable(uint32_t src) const {
    const uint32_t bank = src / kBitsPerBank;
    const uint32_t mask = 1u << (src % kBitsPerBank);
    if (!((raw_[bank] | swforce_[bank]) & enable_[bank] & mask)) return false;
    const uint32_t gate = (secure_[bank] & mask) ? kIntctrlEn : kIntctrlNsen;
    if (!(intctrl_ & gate)) return false;
    /* RM §57.3.3.4 PRIOMASK: an interrupt reaches the CPU only if its priority is
       higher than PRIOMASK; equal-or-lower is masked. The PRIORITY register (RM
       57-22) defines priority 0 as highest, so higher priority = lower value ⇒
       pass iff prio < mask. */
    const uint32_t prio = (priority_[src >> 2] >> ((src & 3u) * 8u)) & 0xFFu;
    return prio < (priomask_ & 0xFFu);
}

int Imx51Tzic::ComputeActiveSource() const {
    int      active      = -1;
    uint32_t active_prio = 0xFFu;
    for (uint32_t b = 0; b < kBankCount; ++b) {
        uint32_t cand = (raw_[b] | swforce_[b]) & enable_[b];
        while (cand != 0) {
            const uint32_t src = b * kBitsPerBank + std::countr_zero(cand);
            cand &= cand - 1u;
            if (!SourceDeliverable(src)) continue;
            /* RM p57-22: priority 0 is highest, so lowest priority value wins;
               std::countr_zero walks low→high so ties keep the lowest source. */
            const uint32_t prio = (priority_[src >> 2] >> ((src & 3u) * 8u)) & 0xFFu;
            if (active < 0 || prio < active_prio) {
                active      = static_cast<int>(src);
                active_prio = prio;
            }
        }
    }
    return active;
}

bool Imx51Tzic::HasPendingUnmasked() const { return ComputeActiveSource() >= 0; }

void Imx51Tzic::AssertIrq(int source_bit) {
    if (source_bit < 0 || source_bit >= static_cast<int>(kSourceCount)) {
        LOG(Caution, "Imx51Tzic::AssertIrq: source %d out of range (128)\n", source_bit);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    std::lock_guard<std::mutex> lk(state_mutex_);
    raw_[source_bit / kBitsPerBank] |= 1u << (source_bit % kBitsPerBank);
    if (HasPendingUnmasked()) emu_.Get<ArmJit>().SetInterruptPending();
}

void Imx51Tzic::DeAssertIrq(int source_bit) {
    if (source_bit < 0 || source_bit >= static_cast<int>(kSourceCount)) {
        LOG(Caution, "Imx51Tzic::DeAssertIrq: source %d out of range (128)\n", source_bit);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    std::lock_guard<std::mutex> lk(state_mutex_);
    raw_[source_bit / kBitsPerBank] &= ~(1u << (source_bit % kBitsPerBank));
    auto& jit = emu_.Get<ArmJit>();
    if (HasPendingUnmasked()) jit.SetInterruptPending();
    else                      jit.ClearInterruptPending();
}

void Imx51Tzic::AssertSubIrq(int /*main_bit*/, int /*sub_bit*/) {
    LOG(Caution, "Imx51Tzic::AssertSubIrq: TZIC has no sub-interrupt layer; "
            "caller is using the wrong INTC model for this SoC\n");
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

int Imx51Tzic::BankInSet(uint32_t off, uint32_t base) {
    return (off >= base && off < base + 0x10u) ? static_cast<int>((off - base) / 4u) : -1;
}

uint32_t Imx51Tzic::ReadReg(uint32_t off) {
    std::lock_guard<std::mutex> lk(state_mutex_);

    if (off >= kOffPriority0 && off < kOffPriority0 + 32u * 4u)
        return priority_[(off - kOffPriority0) / 4u];

    int b;
    if ((b = BankInSet(off, kOffIntsec0))   >= 0) return secure_[b];
    if ((b = BankInSet(off, kOffEnset0))    >= 0) return enable_[b];
    if ((b = BankInSet(off, kOffEnclear0))  >= 0) return enable_[b];
    if ((b = BankInSet(off, kOffSrcset0))   >= 0) return swforce_[b];
    if ((b = BankInSet(off, kOffSrcclear0)) >= 0) return swforce_[b];
    if ((b = BankInSet(off, kOffPnd0))      >= 0)
        return (raw_[b] | swforce_[b]) & enable_[b];
    if ((b = BankInSet(off, kOffHipnd0))    >= 0) {
        uint32_t hi = 0;
        for (uint32_t bit = 0; bit < kBitsPerBank; ++bit)
            if (SourceDeliverable(b * kBitsPerBank + bit)) hi |= 1u << bit;
        return hi;
    }
    if ((b = BankInSet(off, kOffWakeup0)) >= 0) return wakeup_[b];

    switch (off) {
    case kOffIntctrl:  return intctrl_;
    case kOffInttype:  return kInttype;
    case kOffPriomask: return priomask_;
    case kOffSyncctrl: return syncctrl_;
    case kOffDsmint:   return dsmint_;
    }
    LOG(Caution, "Imx51Tzic::ReadReg: offset 0x%X outside the documented "
            "TZIC register map (RM Table 57-1)\n", off);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

void Imx51Tzic::WriteReg(uint32_t off, uint32_t value) {
    {
        std::lock_guard<std::mutex> lk(state_mutex_);

        if (off >= kOffPriority0 && off < kOffPriority0 + 32u * 4u) {
            priority_[(off - kOffPriority0) / 4u] = value;
        } else {
            int b;
            if ((b = BankInSet(off, kOffIntsec0))   >= 0) secure_[b]   = value;
            else if ((b = BankInSet(off, kOffEnset0))    >= 0) enable_[b]  |=  value;
            else if ((b = BankInSet(off, kOffEnclear0))  >= 0) enable_[b]  &= ~value;
            else if ((b = BankInSet(off, kOffSrcset0))   >= 0) swforce_[b] |=  value;
            else if ((b = BankInSet(off, kOffSrcclear0)) >= 0) swforce_[b] &= ~value;
            else if (BankInSet(off, kOffPnd0) >= 0 || BankInSet(off, kOffHipnd0) >= 0) {
                /* PND / HIPND are read-only status. */
            } else if ((b = BankInSet(off, kOffWakeup0)) >= 0) {
                wakeup_[b] = value;   /* inert in CERF (no suspend); see header */
            } else {
                switch (off) {
                case kOffIntctrl:
                    /* EN updated always; NSEN only when its write-mask bit is set
                       (RM §57.3.3.1). NSENMASK is a strobe, not stored. */
                    intctrl_ = (intctrl_ & ~kIntctrlEn) | (value & kIntctrlEn);
                    if (value & kIntctrlNsenMask)
                        intctrl_ = (intctrl_ & ~kIntctrlNsen) | (value & kIntctrlNsen);
                    break;
                case kOffInttype:  /* read-only */            break;
                case kOffPriomask: priomask_ = value & 0xFFu; break;
                case kOffSyncctrl: syncctrl_ = value;         break;
                case kOffDsmint:   dsmint_   = value;         break;
                default:
                    LOG(Caution, "Imx51Tzic::WriteReg: offset 0x%X outside the "
                            "documented TZIC register map (RM Table 57-1)\n", off);
                    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
                }
            }
        }
    }

    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        auto& jit = emu_.Get<ArmJit>();
        if (HasPendingUnmasked()) jit.SetInterruptPending();
        else                      jit.ClearInterruptPending();
    }
}

void Imx51Tzic::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    w.WriteBytes("raw", raw_,      sizeof(raw_));
    w.WriteBytes("enable", enable_,   sizeof(enable_));
    w.WriteBytes("secure", secure_,   sizeof(secure_));
    w.WriteBytes("swforce", swforce_,  sizeof(swforce_));
    w.WriteBytes("wakeup", wakeup_,   sizeof(wakeup_));
    w.WriteBytes("priority", priority_, sizeof(priority_));
    w.Write("intctrl", intctrl_);
    w.Write("priomask", priomask_);
    w.Write("syncctrl", syncctrl_);
    w.Write("dsmint", dsmint_);
}

void Imx51Tzic::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    r.ReadBytes("raw", raw_,      sizeof(raw_));
    r.ReadBytes("enable", enable_,   sizeof(enable_));
    r.ReadBytes("secure", secure_,   sizeof(secure_));
    r.ReadBytes("swforce", swforce_,  sizeof(swforce_));
    r.ReadBytes("wakeup", wakeup_,   sizeof(wakeup_));
    r.ReadBytes("priority", priority_, sizeof(priority_));
    r.Read("intctrl", intctrl_);
    r.Read("priomask", priomask_);
    r.Read("syncctrl", syncctrl_);
    r.Read("dsmint", dsmint_);
}

void Imx51Tzic::PostRestore() {
    /* Re-derive the JIT IRQ latch from restored state after every peripheral's
       RestoreState has run - the INTC owns the CPU IRQ line. */
    std::lock_guard<std::mutex> lk(state_mutex_);
    auto& jit = emu_.Get<ArmJit>();
    if (HasPendingUnmasked()) jit.SetInterruptPending();
    else                      jit.ClearInterruptPending();
}

namespace {

constexpr uint32_t kTzicMmioBasePa = 0xE0000000u;
constexpr uint32_t kTzicMmioSize   = 0x00004000u;  /* 16 KB */

class Imx51TzicMmio : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx51;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kTzicMmioBasePa; }
    uint32_t MmioSize() const override { return kTzicMmioSize; }

    uint32_t ReadWord(uint32_t addr) override {
        return static_cast<Imx51Tzic&>(emu_.Get<IrqController>()).ReadReg(addr - MmioBase());
    }
    void WriteWord(uint32_t addr, uint32_t value) override {
        static_cast<Imx51Tzic&>(emu_.Get<IrqController>()).WriteReg(addr - MmioBase(), value);
    }

    void SaveState(StateWriter& w) override {
        static_cast<Imx51Tzic&>(emu_.Get<IrqController>()).SaveState(w);
    }
    void RestoreState(StateReader& r) override {
        static_cast<Imx51Tzic&>(emu_.Get<IrqController>()).RestoreState(r);
    }
    void PostRestore() override {
        static_cast<Imx51Tzic&>(emu_.Get<IrqController>()).PostRestore();
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(Imx51Tzic, IrqController);
REGISTER_SERVICE   (Imx51TzicMmio);
