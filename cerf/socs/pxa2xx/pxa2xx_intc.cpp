#include "pxa2xx_intc.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../core/rate_probe.h"
#include "../../jit/arm/arm_cpu.h"
#include "../../jit/arm/arm_jit.h"
#include "../../jit/arm/arm_mmu.h"
#include "../../jit/arm/cpu_state.h"
#include "../../state/state_stream.h"

#include <mutex>

bool Pxa2xxIntc::SplitSource(int source_bit, uint32_t& bank, uint32_t& bit) const {
    if (source_bit < 0) return false;
    const uint32_t id = static_cast<uint32_t>(source_bit);
    if (id >= 32u * kBanks) return false;
    bank = id / 32u;
    bit  = id % 32u;
    return bank == 0u || HasSecondBank();
}

uint32_t Pxa2xxIntc::IprIndex(uint32_t off) const {
    if (off <= kIprLoEnd) return (off - kIprLo) / 4u;
    return 32u + (off - kIprHi) / 4u;
}

bool Pxa2xxIntc::IsKnown(uint32_t off) const {
    switch (off) {
    case kIcip: case kIcmr: case kIclr: case kIcfp: case kIcpr: case kIccr:
        return true;
    case kIchp: case kIcip2: case kIcmr2: case kIclr2: case kIcfp2: case kIcpr2:
        return HasSecondBank();
    default:
        break;
    }
    if (!HasSecondBank() || (off & 0x3u) != 0) return false;
    return (off >= kIprLo && off <= kIprLoEnd) || (off >= kIprHi && off <= kIprHiEnd);
}

void Pxa2xxIntc::NotifyLocked() {
    if (IcFpAllLocked() != 0) {
        LOG(SocIntc, "FIQ asserted (ICFP=0x%08X) - FIQ delivery not wired "
                     "through ArmJit\n", IcFpAllLocked());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    auto& jit = emu_.Get<ArmJit>();
    if (IcIpAllLocked() != 0) {
        jit.SetInterruptPending();
#if CERF_DEV_MODE
        emu_.Get<RateProbe>().Inc(RateProbe::Counter::JitPendSet);
#endif
    } else {
        jit.ClearInterruptPending();
#if CERF_DEV_MODE
        emu_.Get<RateProbe>().Inc(RateProbe::Counter::JitPendClr);
#endif
    }
}

void Pxa2xxIntc::AssertIrq(int source_bit) {
    uint32_t bank = 0, bit = 0;
    if (!SplitSource(source_bit, bank, bit)) {
        LOG(Caution, "Pxa2xxIntc::AssertIrq: peripheral ID %d has no bit in this "
                     "interrupt controller\n", source_bit);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const uint32_t mask = 1u << bit;
    std::lock_guard<std::mutex> guard(state_mtx_);
    if ((icpr_[bank] & mask) == 0) {
        icpr_[bank] |= mask;
#if CERF_DEV_MODE
        emu_.Get<RateProbe>().Inc(RateProbe::Counter::IntcAsserts);
#endif
        NotifyLocked();
    }
}

void Pxa2xxIntc::DeAssertIrq(int source_bit) {
    uint32_t bank = 0, bit = 0;
    if (!SplitSource(source_bit, bank, bit)) {
        LOG(Caution, "Pxa2xxIntc::DeAssertIrq: peripheral ID %d has no bit in this "
                     "interrupt controller\n", source_bit);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const uint32_t mask = 1u << bit;
    std::lock_guard<std::mutex> guard(state_mtx_);
    if ((icpr_[bank] & mask) != 0) {
        icpr_[bank] &= ~mask;
#if CERF_DEV_MODE
        emu_.Get<RateProbe>().Inc(RateProbe::Counter::IntcDeasserts);
#endif
        NotifyLocked();
    }
}

void Pxa2xxIntc::AssertSubIrq(int main_source_bit, int sub_source_bit) {
    LOG(Caution, "Pxa2xxIntc::AssertSubIrq(%d, %d) - Table 25-16 lists no "
                 "second-level source register in this interrupt controller\n",
        main_source_bit, sub_source_bit);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

void Pxa2xxIntc::DeliverPendingIrq() {
    bool ready = false;
    {
        std::lock_guard<std::mutex> guard(state_mtx_);
        ready = IcIpAllLocked() != 0;
    }
    if (!ready) return;

    auto&        cpu   = emu_.Get<ArmCpu>();
    ArmCpuState* state = cpu.State();
    if (state->cpsr.bits.irq_disable) return;
    cpu.RaiseIrqException(state->gprs[ArmGpr::kR15]);
}

void Pxa2xxIntc::SetSourceLevel(uint32_t mask, uint32_t level) {
    std::lock_guard<std::mutex> guard(state_mtx_);
    const uint32_t old_icip = IcIpAllLocked();
    const uint32_t old_icfp = IcFpAllLocked();
    icpr_[0] = (icpr_[0] & ~mask) | (level & mask);
    if (IcIpAllLocked() != old_icip || IcFpAllLocked() != old_icfp) {
        NotifyLocked();
    }
}

namespace {

void HaltWideIchpField(uint32_t pid, const char* which) {
    LOG(Caution, "Pxa2xxIntc: peripheral ID %u has the highest %s priority but "
                 "the ICHP field holds five bits\n", pid, which);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

}  /* namespace */

/* Intel PXA27x Developer's Manual 280000-001 Section 25.5.7 (page 25-28):
   "Priority 0 is the highest priority and 39 is the lowest priority." "The
   IPRx[31] is the valid bit". "if an invalid or non-existing peripheral ID (40
   or 52, for example) is programmed ... it will be ignored". */
bool Pxa2xxIntc::HighestPriorityLocked(uint64_t pending, uint32_t& pid) const {
    for (uint32_t prio = 0; prio < kIprSlots; ++prio) {
        if ((ipr_[prio] & kIprVal) == 0) continue;
        const uint32_t candidate = ipr_[prio] & kIprPid;
        if (candidate >= kIprSlots) continue;
        if (((pending >> candidate) & 1u) == 0) continue;
        pid = candidate;
        return true;
    }
    return false;
}

/* Intel PXA27x Developer's Manual 280000-001 Section 25.5.8 (page 25-29): "If
   ICPs are partially defined, the ICHP uses the partial information to determine
   the highest priority peripheral. If none of the ICP fields is defined, ICHP
   contains invalidated values in both fields." */
uint32_t Pxa2xxIntc::IchpLocked() {
    const uint64_t irq_pending = static_cast<uint64_t>(IcIpLocked(0)) |
                                 (static_cast<uint64_t>(IcIpLocked(1)) << 32);
    const uint64_t fiq_pending = static_cast<uint64_t>(IcFpLocked(0)) |
                                 (static_cast<uint64_t>(IcFpLocked(1)) << 32);

    /* Table 25-15 (page 25-30): "20:16 R IRQ ... When no interrupt has occurred,
       this bit is set to -1."; "4:0 R FIQ ... When no interrupt has occurred,
       this bit is set to -1." The same table's Reset row reads 0 for all 32
       bits. */
    uint32_t irq   = kIchpFieldMask;
    uint32_t fiq   = kIchpFieldMask;
    uint32_t valid = 0;
    uint32_t pid   = 0;
    if (HighestPriorityLocked(irq_pending, pid)) {
        if (pid > kIchpFieldMask) HaltWideIchpField(pid, "IRQ");
        irq    = pid;
        valid |= kIchpValIrq;
    }
    if (HighestPriorityLocked(fiq_pending, pid)) {
        if (pid > kIchpFieldMask) HaltWideIchpField(pid, "FIQ");
        fiq    = pid;
        valid |= kIchpValFiq;
    }
    const uint32_t ichp = valid | (irq << kIchpIrqShift) | fiq;
    return ichp;
}

uint32_t Pxa2xxIntc::ReadRegLocked(uint32_t off) {
    switch (off) {
    case kIcip:  return IcIpLocked(0);
    case kIcmr:  return icmr_[0];
    case kIclr:  return iclr_[0];
    case kIcfp:  return IcFpLocked(0);
    case kIcpr:  return icpr_[0];
    case kIccr:  return iccr_;
    case kIcip2: return IcIpLocked(1);
    case kIcmr2: return icmr_[1];
    case kIclr2: return iclr_[1];
    case kIcfp2: return IcFpLocked(1);
    case kIcpr2: return icpr_[1];
    case kIchp:
        if (HasSecondBank()) return IchpLocked();
        break;
    default:
        break;
    }
    if (!IsKnown(off)) {
        LOG(Caution, "Pxa2xxIntc: read of offset 0x%02X\n", off);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    return ipr_[IprIndex(off)];
}

void Pxa2xxIntc::WriteRegLocked(uint32_t off, uint32_t value) {
    const uint32_t old_icip = IcIpAllLocked();
    const uint32_t old_icfp = IcFpAllLocked();
    switch (off) {
    case kIcmr:
#if CERF_DEV_MODE
        if (((icmr_[0] ^ value) >> 26) & 1u)
            LOG(SocIntc, "[INTC] ICMR bit26(OST) %s (icmr 0x%08X->0x%08X)\n",
                (value >> 26) & 1u ? "UNMASK" : "MASK", icmr_[0], value);
#endif
        icmr_[0] = value; break;
    case kIclr:  iclr_[0] = value; break;
    case kIcmr2: icmr_[1] = value; break;
    case kIclr2: iclr_[1] = value; break;
    case kIccr:  iccr_ = value & kIccrMask; break;
    /* Intel PXA27x Developer's Manual 280000-001 Tables 25-3, 25-5, 25-7 and
       25-15: every ICPR, ICIP, ICFP and ICHP bit has access R. */
    case kIcip: case kIcfp: case kIcpr:
    case kIcip2: case kIcfp2: case kIcpr2: case kIchp: break;
    default:
        if (!IsKnown(off)) {
            LOG(Caution, "Pxa2xxIntc: write 0x%08X to offset 0x%02X\n", value, off);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        ipr_[IprIndex(off)] = value & kIprMask;
        break;
    }
    if (IcIpAllLocked() != old_icip || IcFpAllLocked() != old_icfp) {
        NotifyLocked();
    }
}

uint32_t Pxa2xxIntc::ReadReg(uint32_t off) {
    std::lock_guard<std::mutex> guard(state_mtx_);
    return ReadRegLocked(off);
}

void Pxa2xxIntc::WriteReg(uint32_t off, uint32_t value) {
    std::lock_guard<std::mutex> guard(state_mtx_);
    WriteRegLocked(off, value);
}

uint8_t Pxa2xxIntc::ReadByteAt(uint32_t off) {
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8u;
    std::lock_guard<std::mutex> guard(state_mtx_);
    return static_cast<uint8_t>((ReadRegLocked(base) >> shift) & 0xFFu);
}

void Pxa2xxIntc::WriteByteAt(uint32_t off, uint8_t value) {
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8u;
    std::lock_guard<std::mutex> guard(state_mtx_);
    const uint32_t cleared = ReadRegLocked(base) & ~(0xFFu << shift);
    WriteRegLocked(base, cleared | (static_cast<uint32_t>(value) << shift));
}

void Pxa2xxIntc::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> guard(state_mtx_);
    for (uint32_t b = 0; b < kBanks; ++b) {
        w.Write(icpr_[b]);
        w.Write(icmr_[b]);
        w.Write(iclr_[b]);
    }
    w.Write(iccr_);
    for (uint32_t i = 0; i < kIprSlots; ++i) w.Write(ipr_[i]);
}

void Pxa2xxIntc::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> guard(state_mtx_);
    for (uint32_t b = 0; b < kBanks; ++b) {
        r.Read(icpr_[b]);
        r.Read(icmr_[b]);
        r.Read(iclr_[b]);
    }
    r.Read(iccr_);
    for (uint32_t i = 0; i < kIprSlots; ++i) r.Read(ipr_[i]);
}

void Pxa2xxIntc::PostRestore() {
    std::lock_guard<std::mutex> guard(state_mtx_);
    NotifyLocked();
}
