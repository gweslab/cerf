#include "pxa255_intc.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../core/rate_probe.h"
#include "../../boards/board_detector.h"
#include "../../jit/arm_jit.h"
#include "../../peripherals/peripheral_dispatcher.h"

bool Pxa255Intc::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    return bd && bd->GetSoc() == SocFamily::PXA25x;
}

void Pxa255Intc::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void Pxa255Intc::NotifyLocked() {
    if (IcFpLocked() != 0) {
        LOG(SocIntc, "FIQ asserted (ICFP=0x%08X) — FIQ delivery not wired "
                     "through ArmJit\n", IcFpLocked());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    auto& jit = emu_.Get<ArmJit>();
    if (IcIpLocked() != 0) {
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

void Pxa255Intc::AssertSource(uint32_t bit_index) {
    if (bit_index >= 32) return;
    const uint32_t mask = 1u << bit_index;
    std::lock_guard<std::mutex> guard(state_mtx_);
    if ((icpr_ & mask) == 0) {
        icpr_ |= mask;
#if CERF_DEV_MODE
        emu_.Get<RateProbe>().Inc(RateProbe::Counter::IntcAsserts);
        if (bit_index == 26u)
            LOG(SocIntc, "[INTC] OST(bit26) assert: icmr=0x%08X masked=%u "
                         "icip26=%u\n",
                icmr_, (icmr_ >> 26) & 1u ? 0u : 1u, (IcIpLocked() >> 26) & 1u);
#endif
        NotifyLocked();
    }
#if CERF_DEV_MODE
    else if (bit_index == 26u) {
        LOG(SocIntc, "[INTC] OST(bit26) assert NOOP (icpr already set) icmr=0x%08X\n",
            icmr_);
    }
#endif
}

void Pxa255Intc::DeassertSource(uint32_t bit_index) {
    if (bit_index >= 32) return;
    const uint32_t mask = 1u << bit_index;
    std::lock_guard<std::mutex> guard(state_mtx_);
    if ((icpr_ & mask) != 0) {
        icpr_ &= ~mask;
#if CERF_DEV_MODE
        emu_.Get<RateProbe>().Inc(RateProbe::Counter::IntcDeasserts);
#endif
        NotifyLocked();
    }
}

uint32_t Pxa255Intc::ReadRegLocked(uint32_t off) const {
    switch (off) {
        case 0x00: return IcIpLocked();  /* ICIP */
        case 0x04: return icmr_;         /* ICMR */
        case 0x08: return iclr_;         /* ICLR */
        case 0x0C: return IcFpLocked();  /* ICFP */
        case 0x10: return icpr_;         /* ICPR */
        case 0x14: return iccr_;         /* ICCR */
        default:   return 0;
    }
}

void Pxa255Intc::WriteRegLocked(uint32_t off, uint32_t value) {
    const uint32_t old_icip = IcIpLocked();
    const uint32_t old_icfp = IcFpLocked();
    switch (off) {
        case 0x04:
#if CERF_DEV_MODE
            if (((icmr_ ^ value) >> 26) & 1u)
                LOG(SocIntc, "[INTC] ICMR bit26(OST) %s (icmr 0x%08X->0x%08X)\n",
                    (value >> 26) & 1u ? "UNMASK" : "MASK", icmr_, value);
#endif
            icmr_ = value; break;              /* ICMR */
        case 0x08: iclr_ = value; break;       /* ICLR */
        case 0x14: iccr_ = value & 0x1u; break;/* ICCR — DIM (bit0). */
        default:   break;                      /* ICIP/ICFP/ICPR read-only. */
    }
    if (IcIpLocked() != old_icip || IcFpLocked() != old_icfp) {
        NotifyLocked();
    }
}

uint8_t Pxa255Intc::ReadByte(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsKnown(base)) HaltUnsupportedAccess("ReadByte", addr, 0);
    std::lock_guard<std::mutex> guard(state_mtx_);
    return static_cast<uint8_t>((ReadRegLocked(base) >> shift) & 0xFFu);
}

uint32_t Pxa255Intc::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("ReadWord", addr, 0);
    std::lock_guard<std::mutex> guard(state_mtx_);
    return ReadRegLocked(off);
}

void Pxa255Intc::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsKnown(base)) HaltUnsupportedAccess("WriteByte", addr, value);
    std::lock_guard<std::mutex> guard(state_mtx_);
    const uint32_t cur     = ReadRegLocked(base);
    const uint32_t cleared = cur & ~(0xFFu << shift);
    WriteRegLocked(base, cleared | (static_cast<uint32_t>(value) << shift));
}

void Pxa255Intc::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("WriteWord", addr, value);
    std::lock_guard<std::mutex> guard(state_mtx_);
    WriteRegLocked(off, value);
}

REGISTER_SERVICE(Pxa255Intc);
