#include "sa11xx_intc.h"

#include "../guest_cpu_reset.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../core/rate_probe.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../jit/arm/arm_jit.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

bool Sa11xxIntc::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
}

void Sa11xxIntc::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
    /* SA-1110 Dev Man §9.2.1.5: DIM "is cleared during all resets"; §9.2.1.3 /
       §9.2.1.4: the ICMR and ICLR values are unknown at reset. */
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        std::lock_guard<std::mutex> guard(state_mtx_);
        const bool old_wake = IdleWakeLocked();
        iccr_ = 0u;
        if (IdleWakeLocked() != old_wake) NotifyLocked();
    });
}

void Sa11xxIntc::NotifyLocked() {
    if (IcFpLocked() != 0) {
        LOG(SocIntc, "FIQ asserted (ICFP=0x%08X) - FIQ delivery not "
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
    jit.SetIdleWake(IdleWakeLocked());
}

void Sa11xxIntc::AssertSource(uint32_t bit_index) {
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

void Sa11xxIntc::DeassertSource(uint32_t bit_index) {
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

void Sa11xxIntc::SetSourceLevel(uint32_t mask, uint32_t level) {
    std::lock_guard<std::mutex> guard(state_mtx_);
    const uint32_t old_icip = IcIpLocked();
    const uint32_t old_icfp = IcFpLocked();
    const bool     old_wake = IdleWakeLocked();
    icpr_ = (icpr_ & ~mask) | (level & mask);
    if (IcIpLocked() != old_icip || IcFpLocked() != old_icfp ||
        IdleWakeLocked() != old_wake) {
        NotifyLocked();
    }
}

uint32_t Sa11xxIntc::GetIcpr() const {
    std::lock_guard<std::mutex> guard(state_mtx_);
    return icpr_;
}
uint32_t Sa11xxIntc::GetIcmr() const {
    std::lock_guard<std::mutex> guard(state_mtx_);
    return icmr_;
}
uint32_t Sa11xxIntc::GetIclr() const {
    std::lock_guard<std::mutex> guard(state_mtx_);
    return iclr_;
}
uint32_t Sa11xxIntc::GetIcIp() const {
    std::lock_guard<std::mutex> guard(state_mtx_);
    return IcIpLocked();
}

uint32_t Sa11xxIntc::ReadRegLocked(uint32_t off) const {
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

void Sa11xxIntc::WriteRegLocked(uint32_t off, uint32_t value) {
    const uint32_t old_icip = IcIpLocked();
    const uint32_t old_icfp = IcFpLocked();
    const bool     old_wake = IdleWakeLocked();
    switch (off) {
        case 0x00: break;
        case 0x04: icmr_ = value; break;
        case 0x08: iclr_ = value; break;
        case 0x0C: iccr_ = value & 0x1u; break;
        case 0x10: break;
        case 0x20: break;
        default:   break;
    }
    if (IcIpLocked() != old_icip || IcFpLocked() != old_icfp ||
        IdleWakeLocked() != old_wake) {
        NotifyLocked();
    }
}

uint8_t Sa11xxIntc::ReadByte(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsKnown(base)) HaltUnsupportedAccess("ReadByte", addr, 0);
    std::lock_guard<std::mutex> guard(state_mtx_);
    return static_cast<uint8_t>((ReadRegLocked(base) >> shift) & 0xFFu);
}

uint32_t Sa11xxIntc::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("ReadWord", addr, 0);
    std::lock_guard<std::mutex> guard(state_mtx_);
    return ReadRegLocked(off);
}

void Sa11xxIntc::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsKnown(base)) HaltUnsupportedAccess("WriteByte", addr, value);
    std::lock_guard<std::mutex> guard(state_mtx_);
    const uint32_t cur     = ReadRegLocked(base);
    const uint32_t cleared = cur & ~(0xFFu << shift);
    WriteRegLocked(base, cleared | (static_cast<uint32_t>(value) << shift));
}

void Sa11xxIntc::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("WriteWord", addr, value);
    std::lock_guard<std::mutex> guard(state_mtx_);
    WriteRegLocked(off, value);
}

void Sa11xxIntc::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> guard(state_mtx_);
    w.Write("icpr", icpr_);
    w.Write("icmr", icmr_);
    w.Write("iclr", iclr_);
    w.Write("iccr", iccr_);
}

void Sa11xxIntc::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> guard(state_mtx_);
    r.Read("icpr", icpr_);
    r.Read("icmr", icmr_);
    r.Read("iclr", iclr_);
    r.Read("iccr", iccr_);
}

void Sa11xxIntc::PostRestore() {
    std::lock_guard<std::mutex> guard(state_mtx_);
    NotifyLocked();   /* drive the JIT pending bit from the restored icpr_/icmr_ */
}

REGISTER_SERVICE(Sa11xxIntc);
