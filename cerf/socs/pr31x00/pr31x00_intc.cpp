#include "pr31x00_intc.h"

#include "../../boards/board_context.h"
#include "pr31500_id.h"
#include "pr31700_id.h"
#include "../../core/cerf_emulator.h"
#include "../../jit/mips/mips_jit.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

#include <cstdint>

namespace {

constexpr uint32_t kBase = 0x10C00100u;

constexpr uint32_t kOffStatus0 = 0x00u;   /* $100..$110 read = Status 1..5, write = Clear 1..5 */
constexpr uint32_t kOffStatus6 = 0x14u;   /* $114 */
constexpr uint32_t kOffEnable0 = 0x18u;   /* $118..$128 */
constexpr uint32_t kOffEnable6 = 0x2Cu;

/* Interrupt Status 6 (§8.3.6), read-only apart from PWROKNMI<29>. IRQHIGH<31> and
   IRQLOW<30> are the module's two named nets, each an OR tree AND'ed with GLOBALEN
   before it leaves the module (Figure 8.2.1); INTVECT[3:0]<5:2> comes off the priority
   encoder, which takes the Priority Mask but not GLOBALEN. */
constexpr uint32_t kStatus6IrqHigh      = 1u << 31;
constexpr uint32_t kStatus6IrqLow       = 1u << 30;
constexpr uint32_t kStatus6IntVectShift = 2;

constexpr uint32_t kSets = 5u;

/* Enable Interrupt 6 (§8.3.17): GLOBALEN<18> IRQPRITEST<17> IRQTEST<16>
   PRIORITYMASK[15:0]<15:0>; bits 31-19 reserved. */
constexpr uint32_t kGlobalEn         = 1u << 18;
constexpr uint32_t kIrqPriTest       = 1u << 17;
constexpr uint32_t kIrqTest          = 1u << 16;
constexpr uint32_t kPriorityMask     = 0x0000FFFFu;
constexpr uint32_t kEnable6Reserved  = 0xFFF80000u;

/* An Enable Interrupt register maps one-to-one onto its Status register
   (§8.3.13-§8.3.16), so each takes its Status register's reserved bits:
   Status 1 reserves 4-0 (§8.3.1), Status 2 reserves 1-0 (§8.3.2), and
   Status 3, 4 and 5 assign all 32 bits (§8.3.3-§8.3.5). */
constexpr uint32_t kEnableReserved[5] = { 0x0000001Fu, 0x00000003u, 0u, 0u, 0u };

/* IRQHIGH -> TX39/H interrupt bit 4, IRQLOW -> interrupt bit 2 (§8.2.2). Cause
   IP[5:0] occupies bits 15:10 (TMPR39xx-um Fig 6-2), so Int2 is bit 12 and Int4
   is bit 14. */
constexpr uint32_t kIrqLowIp  = 1u << 12;
constexpr uint32_t kIrqHighIp = 1u << 14;

/* The 15 high priority sources by priority level, 15 highest; level 0 selects the
   standard interrupt handler (§8.3.6). Each level ORs up to two terms, naming a
   Status set (0-4 == Status 1-5) and a bit mask in it. */
struct HighPrioTerm {
    uint32_t set;
    uint32_t mask;
};
constexpr HighPrioTerm kHighPrio[16][2] = {
    /*  0 */ { { 0, 0 }, { 0, 0 } },
    /*  1 IOPOSINT(0) | IONEGINT(0)               */ { { 4, (1u << 7) | (1u << 0) }, { 0, 0 } },
    /*  2 CHIDMACNTINT                            */ { { 0, 1u << 27 }, { 0, 0 } },
    /*  3 TELDMACNTINT                            */ { { 0, 1u << 17 }, { 0, 0 } },
    /*  4 SNDDMACNTINT                            */ { { 0, 1u << 18 }, { 0, 0 } },
    /*  5 MBUSDMAFULLINT                          */ { { 1, 1u << 5 }, { 0, 0 } },
    /*  6 MFIONEGINT(1,0) | IONEGINT(6,5)         */ { { 3, (1u << 1) | (1u << 0) }, { 4, (1u << 6) | (1u << 5) } },
    /*  7 MFIONEGINT(19..16)                      */ { { 3, 0xFu << 16 }, { 0, 0 } },
    /*  8 MFIOPOSINT(1,0) | IOPOSINT(6,5)         */ { { 2, (1u << 1) | (1u << 0) }, { 4, (1u << 13) | (1u << 12) } },
    /*  9 MFIOPOSINT(19..16)                      */ { { 2, 0xFu << 16 }, { 0, 0 } },
    /* 10 UARTBRXINT                              */ { { 1, 1u << 21 }, { 0, 0 } },
    /* 11 UARTARXINT                              */ { { 1, 1u << 31 }, { 0, 0 } },
    /* 12 MBUSPOSINT | MBUSNEGINT                 */ { { 1, (1u << 3) | (1u << 2) }, { 0, 0 } },
    /* 13 PERINT                                  */ { { 4, 1u << 29 }, { 0, 0 } },
    /* 14 ALARMINT                                */ { { 4, 1u << 30 }, { 0, 0 } },
    /* 15 POSPWROKINT | NEGPWROKINT               */ { { 4, (1u << 25) | (1u << 24) }, { 0, 0 } },
};

}  /* namespace */

bool Pr31x00Intc::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    if (!bd) return false;
    const std::string_view soc = bd->GetSocId();
    return soc == SocId::Pr31500 || soc == SocId::Pr31700;
}

void Pr31x00Intc::OnReady() {
    jit_ = &emu_.Get<MipsJit>();
    emu_.Get<PeripheralDispatcher>().Register(this);

    /* Enable Interrupt 1-5 (§8.3.13-§8.3.16): "This register is not cleared upon reset;
       however, the GLOBALEN global interrupt enable bit is cleared upon reset, therefore
       disabling all interrupts." */
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        std::lock_guard<std::mutex> lk(mtx_);
        enable6_ &= ~kGlobalEn;
        RecomputeLocked();
    });
}

/* The priority encoder takes only the Priority Mask and the 15 high priority sources,
   so INTVECT is live while GLOBALEN is clear (Figure 8.2.1); level 0 means none is
   pending. */
uint32_t Pr31x00Intc::HighPriorityLevelLocked() const {
    for (uint32_t level = 15; level >= 1; --level) {
        if ((enable6_ & (1u << level)) == 0u) continue;
        for (const HighPrioTerm& t : kHighPrio[level]) {
            if (t.mask && (status_[t.set] & t.mask)) return level;
        }
    }
    return 0;
}

/* Both OR-trees are AND'ed with GLOBALEN before they leave the module, so IRQLOW and
   IRQHIGH each name one signal that drives a CPU interrupt bit and is read back through
   Interrupt Status 6 (Figure 8.2.1). Computing either one twice lets the two copies
   disagree, and the guest reads a pending interrupt the CPU never took. */
bool Pr31x00Intc::IrqLowLocked() const {
    if ((enable6_ & kGlobalEn) == 0u) return false;
    for (uint32_t i = 0; i < kSets; ++i) {
        if (status_[i] & enable_[i]) return true;
    }
    return false;
}

bool Pr31x00Intc::IrqHighLocked() const {
    return (enable6_ & kGlobalEn) && HighPriorityLevelLocked() != 0u;
}

void Pr31x00Intc::RecomputeLocked() {
    uint32_t ip = 0;
    if (IrqLowLocked())  ip |= kIrqLowIp;
    if (IrqHighLocked()) ip |= kIrqHighIp;
    jit_->SetExternalInterruptLevel(ip);
}

/* SIBSF0INT re-issues at the start of every SIB subframe 0 (§8.3.1). */
void Pr31x00Intc::SetSourceFreeRunning(uint32_t set, uint32_t bits, bool active) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (set >= kSets) {
        HaltUnsupportedAccess("PR31x00 INTC SetSourceFreeRunning set index", set, bits);
    }
    if (active) {
        free_running_[set] |= bits;
        status_[set]       |= bits;
    } else {
        free_running_[set] &= ~bits;
    }
    RecomputeLocked();
}

void Pr31x00Intc::SetGlobalEnable() {
    std::lock_guard<std::mutex> lk(mtx_);
    enable6_ |= kGlobalEn;
    RecomputeLocked();
}

void Pr31x00Intc::SetPending(uint32_t set, uint32_t bits) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (set >= kSets) {
        HaltUnsupportedAccess("PR31x00 INTC SetPending set index", set, bits);
    }
    status_[set] |= bits;
    RecomputeLocked();
}

void Pr31x00Intc::ClearPending(uint32_t set, uint32_t bits) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (set >= kSets) {
        HaltUnsupportedAccess("PR31x00 INTC ClearPending set index", set, bits);
    }
    status_[set] &= ~bits;
    status_[set] |= free_running_[set];
    RecomputeLocked();
}

void Pr31x00Intc::RegisterEnableListener(uint32_t set, uint32_t bits,
                                         std::function<void()> cb) {
    std::unique_lock<std::mutex> lk(mtx_);
    if (set >= kSets) {
        HaltUnsupportedAccess("PR31x00 INTC RegisterEnableListener set index", set, bits);
    }
    const bool already = (enable_[set] & bits) != 0u;
    enable_listeners_.push_back({set, bits, cb});
    lk.unlock();
    if (already) cb();
}

uint32_t Pr31x00Intc::ReadWord(uint32_t addr) {
    std::lock_guard<std::mutex> lk(mtx_);
    const uint32_t off = addr - kBase;

    if (off < kOffStatus0 + kSets * 4u) {
        const uint32_t set = off / 4u;
        return status_[set];
    }

    if (off == kOffStatus6) {
        uint32_t v = (HighPriorityLevelLocked() & 0xFu) << kStatus6IntVectShift;
        if (IrqHighLocked()) v |= kStatus6IrqHigh;
        if (IrqLowLocked())  v |= kStatus6IrqLow;
        return v;
    }

    if (off >= kOffEnable0 && off < kOffEnable0 + kSets * 4u) {
        return enable_[(off - kOffEnable0) / 4u];
    }
    if (off == kOffEnable6) return enable6_;

    HaltUnsupportedAccess("PR31x00 INTC ReadWord", addr, 0);
}

void Pr31x00Intc::WriteWord(uint32_t addr, uint32_t value) {
    std::unique_lock<std::mutex> lk(mtx_);
    const uint32_t off = addr - kBase;

    /* Clear Interrupt 1..5: writing a 1 resets the matching Status bit (§8.2.2); a
       free-running source re-asserts at once (§8.3.1). */
    if (off < kOffStatus0 + kSets * 4u) {
        const uint32_t set = off / 4u;
        status_[set] &= ~value;
        status_[set] |= free_running_[set];
        RecomputeLocked();
        return;
    }

    if (off >= kOffEnable0 && off < kOffEnable0 + kSets * 4u) {
        const uint32_t set = (off - kOffEnable0) / 4u;
        if (value & kEnableReserved[set]) {
            HaltUnsupportedAccess("PR31x00 INTC Enable reserved bits", addr, value);
        }
        enable_[set] = value;
        RecomputeLocked();
        std::vector<std::function<void()>> fire;
        for (const EnableListener& l : enable_listeners_) {
            if (l.set == set && (value & l.bits) != 0u) fire.push_back(l.cb);
        }
        lk.unlock();
        for (const auto& cb : fire) cb();
        return;
    }

    if (off == kOffEnable6) {
        /* IRQTEST / IRQPRITEST drive the IC test path: "should not be set" (§8.3.17). */
        if (value & (kIrqTest | kIrqPriTest)) {
            HaltUnsupportedAccess("PR31x00 INTC Enable6 IRQTEST/IRQPRITEST", addr, value);
        }
        if (value & kEnable6Reserved) {
            HaltUnsupportedAccess("PR31x00 INTC Enable6 reserved bits 31-19", addr, value);
        }
        enable6_ = value & (kGlobalEn | kPriorityMask);
        RecomputeLocked();
        return;
    }

    /* $114 is Interrupt Status 6; its only writable bit is PWROKNMI, which routes
       PWROK to the TX39/H NMI input (§8.3.6). NMI delivery is not modeled. */
    HaltUnsupportedAccess("PR31x00 INTC WriteWord", addr, value);
}

void Pr31x00Intc::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (uint32_t i = 0; i < kSets; ++i) {
        w.Write("status", status_[i]); w.Write("enable", enable_[i]); w.Write("free_running", free_running_[i]);
    }
    w.Write("enable6", enable6_);
}

void Pr31x00Intc::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (uint32_t i = 0; i < kSets; ++i) {
        r.Read("status", status_[i]); r.Read("enable", enable_[i]); r.Read("free_running", free_running_[i]);
    }
    r.Read("enable6", enable6_);
}

void Pr31x00Intc::PostRestore() {
    std::lock_guard<std::mutex> lk(mtx_);
    RecomputeLocked();   /* re-drive the CPU Int level from restored state */
}

REGISTER_SERVICE(Pr31x00Intc);
