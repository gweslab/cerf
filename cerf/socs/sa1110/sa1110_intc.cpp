#include "sa1110_intc.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../core/rate_probe.h"
#include "../../boards/board_detector.h"
#include "../../jit/arm_jit.h"
#include "../../peripherals/peripheral_dispatcher.h"

bool Sa1110Intc::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    return bd && bd->GetSoc() == SocFamily::SA1110;
}

void Sa1110Intc::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void Sa1110Intc::NotifyLocked() {
    if (IcFpLocked() != 0) {
        LOG(SocIntc, "FIQ asserted (ICFP=0x%08X) — FIQ delivery not "
                     "wired through ArmJit\n", IcFpLocked());
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

void Sa1110Intc::AssertSource(uint32_t bit_index) {
    if (bit_index >= 32) return;
    const uint32_t mask = 1u << bit_index;
    std::lock_guard<std::mutex> guard(state_mtx_);
    if ((icpr_ & mask) == 0) {
        icpr_ |= mask;
#if CERF_DEV_MODE
        emu_.Get<RateProbe>().Inc(RateProbe::Counter::IntcAsserts);
#endif
        NotifyLocked();
    }
}

void Sa1110Intc::DeassertSource(uint32_t bit_index) {
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

uint32_t Sa1110Intc::GetIcpr() const {
    std::lock_guard<std::mutex> guard(state_mtx_);
    return icpr_;
}
uint32_t Sa1110Intc::GetIcmr() const {
    std::lock_guard<std::mutex> guard(state_mtx_);
    return icmr_;
}
uint32_t Sa1110Intc::GetIclr() const {
    std::lock_guard<std::mutex> guard(state_mtx_);
    return iclr_;
}
uint32_t Sa1110Intc::GetIcIp() const {
    std::lock_guard<std::mutex> guard(state_mtx_);
    return IcIpLocked();
}

uint32_t Sa1110Intc::ReadRegLocked(uint32_t off) const {
    switch (off) {
        case 0x00: return IcIpLocked();
        case 0x04: return icmr_;
        case 0x08: return iclr_;
        case 0x0C: return iccr_ & 0x1u;
        case 0x10: return IcFpLocked();
        case 0x20: return icpr_;
        default:   return 0;
    }
}

void Sa1110Intc::WriteRegLocked(uint32_t off, uint32_t value) {
    const uint32_t old_icip = IcIpLocked();
    const uint32_t old_icfp = IcFpLocked();
    switch (off) {
        case 0x00: break;
        case 0x04: icmr_ = value; break;
        case 0x08: iclr_ = value; break;
        case 0x0C: iccr_ = value & 0x1u; break;
        case 0x10: break;
        case 0x20: break;
        default:   break;
    }
    /* §9.2: writes to ICLR / ICCR / read-only addresses don't change
       IcIp or IcFp — notifying the JIT on every write is wasted work. */
    if (IcIpLocked() != old_icip || IcFpLocked() != old_icfp) {
        NotifyLocked();
    }
}

uint8_t Sa1110Intc::ReadByte(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsKnown(base)) HaltUnsupportedAccess("ReadByte", addr, 0);
    std::lock_guard<std::mutex> guard(state_mtx_);
    return static_cast<uint8_t>((ReadRegLocked(base) >> shift) & 0xFFu);
}

uint32_t Sa1110Intc::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("ReadWord", addr, 0);
    std::lock_guard<std::mutex> guard(state_mtx_);
    return ReadRegLocked(off);
}

void Sa1110Intc::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsKnown(base)) HaltUnsupportedAccess("WriteByte", addr, value);
    std::lock_guard<std::mutex> guard(state_mtx_);
    const uint32_t cur     = ReadRegLocked(base);
    const uint32_t cleared = cur & ~(0xFFu << shift);
    WriteRegLocked(base, cleared | (static_cast<uint32_t>(value) << shift));
}

void Sa1110Intc::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("WriteWord", addr, value);
    std::lock_guard<std::mutex> guard(state_mtx_);
    WriteRegLocked(off, value);
}

REGISTER_SERVICE(Sa1110Intc);
