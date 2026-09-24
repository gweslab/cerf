#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "omap3530_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../core/virtual_clock.h"
#include "../../core/virtual_timer_list.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../guest_cpu_reset.h"
#include "../irq_controller.h"
#include "../../state/state_stream.h"
#include "omap3530_clocks.h"

#include <cstdint>
#include <mutex>

namespace {

constexpr uint32_t kGptimer1BasePa = 0x48318000u;
constexpr uint32_t kGptimer1Size   = 0x00001000u;
constexpr int      kIrqGptimer1    = 37;

constexpr uint32_t kOffTidr   = 0x00;
constexpr uint32_t kOffTiocp  = 0x10;
constexpr uint32_t kOffTistat = 0x14;
constexpr uint32_t kOffTisr   = 0x18;
constexpr uint32_t kOffTier   = 0x1C;
constexpr uint32_t kOffTwer   = 0x20;
constexpr uint32_t kOffTclr   = 0x24;
constexpr uint32_t kOffTcrr   = 0x28;
constexpr uint32_t kOffTldr   = 0x2C;
constexpr uint32_t kOffTtgr   = 0x30;
constexpr uint32_t kOffTwps   = 0x34;
constexpr uint32_t kOffTmar   = 0x38;
constexpr uint32_t kOffTcar1  = 0x3C;
constexpr uint32_t kOffTsicr  = 0x40;
constexpr uint32_t kOffTcar2  = 0x44;
constexpr uint32_t kOffTpir   = 0x48;
constexpr uint32_t kOffTnir   = 0x4C;
constexpr uint32_t kOffTcvr   = 0x50;
constexpr uint32_t kOffTocr   = 0x54;
constexpr uint32_t kOffTowr   = 0x58;

/* Table 16-18 (printed p. 2622-2623): TIOCP_CFG SOFTRESET [1], "This bit is
   automatically reset by the hardware. During reads, it always returns 0",
   "0x1: The module is reset." */
constexpr uint32_t kTiocpSoftReset = 1u << 1;

/* Table 16-42 (printed p. 2637): TSICR POSTED [2] RW reset 1; SFT [1] "Reset
   software functional registers. This bit is automatically reset by the
   hardware. During reads, it always returns 0", "0x1: The functional registers
   are reset."; bits [31:3] and [0] Reserved, "Reads return 0". */
constexpr uint32_t kTsicrSft    = 1u << 1;
constexpr uint32_t kTsicrPosted = 1u << 2;

/* OMAP3530 TRM SPRUF98Y §16.2.4 (printed p. 2605): the internal interrupt
   sources merge into one module interrupt line, each independently enabled by
   its GPTi.TIER bit. Table 16-22 (printed p. 2625): TISR MAT_IT_FLAG [0],
   OVF_IT_FLAG [1], TCAR_IT_FLAG [2], RW reset 0, "Write 0x1: Status bit
   cleared"; [31:3] Reserved "Reads return 0". */
constexpr uint32_t kIntMat  = 1u << 0;
constexpr uint32_t kIntOvf  = 1u << 1;
constexpr uint32_t kIntTcar = 1u << 2;
constexpr uint32_t kIntMask = kIntMat | kIntOvf | kIntTcar;


/* OMAP3530 TRM SPRUF98Y §16.2.4.2 (printed p. 2607): TCLR[0] ST starts and
   stops the counter; TCLR[1] AR selects autoreload over one-shot. Table 16-10
   (printed p. 2614): TCLR[5] PRE enables the prescaler, TCLR[4:2] PTV selects
   its ratio. §16.2.4.3 (printed p. 2610): TCLR[9:8] TCM selects the capture
   edge on the EVENT_CAPTURE input pin. §16.2.4.4 (printed p. 2611): TCLR[6] CE
   set to 1 continuously compares GPTi.TCRR against GPTi.TMAR, and a match
   "issues an interrupt, if the GPTi.TIER[0] MAT_IT_ENA bit is set". */
constexpr uint32_t kTclrSt    = 1u << 0;
constexpr uint32_t kTclrAr    = 1u << 1;
constexpr uint32_t kTclrPtvSh = 2;
constexpr uint32_t kTclrPtvM  = 7u << kTclrPtvSh;
constexpr uint32_t kTclrPre   = 1u << 5;
constexpr uint32_t kTclrCe    = 1u << 6;

/* OMAP3530 TRM SPRUF98Y TCLR field table (printed p. 2629): SCPWM [7] sets the
   PWM_out default level, TCM [9:8] selects the EVENT_CAPTURE edge, TRG [11:10]
   drives the trigger output on overflow or match, PT [12] selects pulse or
   toggle modulation, CAPT_MODE [13] selects first or second capture and
   GPO_CFG [14] sets the PWM/capture pin direction. All feed the PWM_out and
   EVENT_CAPTURE pins. */
constexpr uint32_t kTclrPinFields =
    (1u << 7) | (3u << 8) | (3u << 10) | (1u << 12) | (1u << 13) | (1u << 14);

/* TCLR field table (printed p. 2629): bits [31:15] are Reserved, "Reads
   return 0". */
constexpr uint32_t kTclrMask = 0x00007FFFu;

constexpr uint64_t kCounterModulo = 0x100000000ull;

class Omap3530Gptimer1 : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Omap3530;
    }
    void OnReady() override {
        entry_ = emu_.Get<VirtualTimerList>().Add([this] { OnDeadline(); });
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            ResetStateLocked();
        }
        SyncIrqLine();
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            {
                std::lock_guard<std::mutex> lk(state_mutex_);
                ResetStateLocked();
            }
            SyncIrqLine();
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kGptimer1BasePa; }
    uint32_t MmioSize() const override { return kGptimer1Size; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override { SyncIrqLine(); }

private:
    /* Table 16-10 (printed p. 2614): "PS = 2^(PTV + 1) if prescaler is
       enabled, or PS = 1 if prescaler is disabled". */
    uint64_t PrescaleLocked() const {
        if ((tclr_ & kTclrPre) == 0) return 1u;
        return 1ull << (((tclr_ & kTclrPtvM) >> kTclrPtvSh) + 1u);
    }

    int64_t TicksToNsCeilLocked(uint64_t ticks) const {
        const uint64_t ns = ticks * kOmap3530NsPerUnit * PrescaleLocked();
        return static_cast<int64_t>((ns + kOmap3530TkPerUnit - 1u) /
                                    kOmap3530TkPerUnit);
    }
    uint64_t ElapsedTicksLocked(int64_t now) const {
        const int64_t ns = now - anchor_ns_;
        if (ns <= 0) return 0;
        return static_cast<uint64_t>(ns) * kOmap3530TkPerUnit /
               (kOmap3530NsPerUnit * PrescaleLocked());
    }

    int64_t NowNs() const { return emu_.Get<VirtualClock>().NowNs(); }

    uint64_t UnfoldedTicksLocked(int64_t now) const {
        if (!running_) return 0;
        const uint64_t total = ElapsedTicksLocked(now);
        return total > folded_ticks_ ? total - folded_ticks_ : 0;
    }

    uint32_t CounterAtLocked(int64_t now) const {
        return tcrr_base_ + static_cast<uint32_t>(UnfoldedTicksLocked(now));
    }

    /* §16.2.4 (printed p. 2605): a free-running upward counter with autoreload
       on overflow, plus compare logic against GPTi.TMAR. */
    uint64_t TicksToOverflowLocked() const {
        return kCounterModulo - tcrr_base_;
    }
    uint64_t TicksToMatchLocked() const {
        if (tmar_ <= tcrr_base_) return kCounterModulo;
        return tmar_ - tcrr_base_;
    }
    uint64_t TicksToNextEventLocked() const {
        uint64_t ticks = TicksToOverflowLocked();
        if ((tclr_ & kTclrCe) != 0) {
            const uint64_t match = TicksToMatchLocked();
            if (match < ticks) ticks = match;
        }
        return ticks;
    }

    void ArmLocked() {
        if (!running_) {
            entry_->Arm(VirtualTimerList::kNoDeadline);
            return;
        }
        entry_->Arm(anchor_ns_ + TicksToNsCeilLocked(folded_ticks_ +
                                                     TicksToNextEventLocked()));
    }

    void LoadCounterLocked(uint32_t value, int64_t now) {
        tcrr_base_     = value;
        anchor_ns_     = now;
        folded_ticks_  = 0;
        one_shot_done_ = false;
        running_       = (tclr_ & kTclrSt) != 0;
    }

    void ResetFunctionalLocked();
    void ResetStateLocked();
    void ApplyTclrWriteLocked(uint32_t new_tclr, int64_t now);
    void CatchUpLocked(int64_t now);
    void OnDeadline();
    void PublishIrqLineLocked(bool high);
    void DriveIrqLineLocked();
    void SyncIrqLine();

    mutable std::mutex       state_mutex_;
    uint32_t                 tisr_          = 0;
    uint32_t                 tier_          = 0;
    uint32_t                 tclr_          = 0;
    uint32_t                 tldr_          = 0;
    uint32_t                 tmar_          = 0;
    uint32_t                 tsicr_         = 0;
    uint32_t                 tcrr_base_     = 0;
    int64_t                  anchor_ns_     = 0;
    uint64_t                 folded_ticks_  = 0;
    bool                     running_       = false;
    bool                     one_shot_done_ = false;
    bool                     irq_high_      = false;
    VirtualTimerList::Entry* entry_         = nullptr;
};

void Omap3530Gptimer1::PublishIrqLineLocked(bool high) {
    irq_high_ = high;
    auto& intc = emu_.Get<IrqController>();
    if (high) intc.AssertIrq  (kIrqGptimer1);
    else      intc.DeAssertIrq(kIrqGptimer1);
}

void Omap3530Gptimer1::DriveIrqLineLocked() {
    const bool high = (tisr_ & tier_ & kIntMask) != 0;
    if (high != irq_high_) PublishIrqLineLocked(high);
}

void Omap3530Gptimer1::SyncIrqLine() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    PublishIrqLineLocked((tisr_ & tier_ & kIntMask) != 0);
}

/* §16.2.4.2 (printed p. 2607): "The timer is stopped and the counter value is
   set to 0 when the module reset is asserted. The timer is maintained at stop
   after the reset is released." */
void Omap3530Gptimer1::ResetFunctionalLocked() {
    tisr_          = 0;
    tier_          = 0;
    tclr_          = 0;
    tldr_          = 0;
    /* Table 16-38 (printed p. 2635): TMAR COMPARE_VALUE [31:0] reset
       0x00000000. */
    tmar_          = 0;
    tcrr_base_     = 0;
    anchor_ns_     = NowNs();
    folded_ticks_  = 0;
    running_       = false;
    one_shot_done_ = false;
    entry_->Arm(VirtualTimerList::kNoDeadline);
}

void Omap3530Gptimer1::ResetStateLocked() {
    ResetFunctionalLocked();
    tsicr_ = kTsicrPosted;
}

/* §16.2.4.2 (printed p. 2607): the counter "can be started and stopped at any
   time through the timer control register (GPTi.TCLR[0] ST bit)". */
void Omap3530Gptimer1::ApplyTclrWriteLocked(uint32_t new_tclr, int64_t now) {
    const uint64_t previous_prescale = PrescaleLocked();
    tclr_ = new_tclr;
    if (PrescaleLocked() != previous_prescale) {
        anchor_ns_    = now;
        folded_ticks_ = 0;
    }

    if ((new_tclr & kTclrSt) == 0) {
        running_       = false;
        one_shot_done_ = false;
    } else if (!running_ && !one_shot_done_) {
        running_      = true;
        anchor_ns_    = now;
        folded_ticks_ = 0;
    }
    ArmLocked();
}

/* §16.2.4.2 (printed p. 2607): "In one-shot mode (the GPTi.TCLR[1] AR bit set
   to 0), the counter is stopped after counting overflow occurs (the counter
   value remains at 0). When the autoreload mode is enabled (the GPTi.TCLR[1]
   AR bit set to 1), the GPTi.TCRR register is reloaded with the timer load
   register (GPTi.TLDR) value after a counting overflow occurs." */
void Omap3530Gptimer1::CatchUpLocked(int64_t now) {
    const bool was_running = running_;
    while (running_) {
        const uint64_t unfolded = UnfoldedTicksLocked(now);
        const uint64_t to_match = TicksToMatchLocked();
        const uint64_t to_ovf   = TicksToOverflowLocked();

        if ((tclr_ & kTclrCe) != 0 && unfolded >= to_match) tisr_ |= kIntMat;

        if (unfolded < to_ovf) {
            folded_ticks_ += unfolded;
            tcrr_base_    += static_cast<uint32_t>(unfolded);
            break;
        }
        folded_ticks_ += to_ovf;
        tisr_         |= kIntOvf;
        if ((tclr_ & kTclrAr) != 0) {
            tcrr_base_     = tldr_;
            one_shot_done_ = false;
        } else {
            tcrr_base_     = 0;
            running_       = false;
            one_shot_done_ = true;
        }
    }
    if (was_running) ArmLocked();
    DriveIrqLineLocked();
}

void Omap3530Gptimer1::OnDeadline() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    CatchUpLocked(NowNs());
}

uint32_t Omap3530Gptimer1::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    std::lock_guard<std::mutex> lk(state_mutex_);
    const int64_t now = NowNs();
    /* §16.2.4.2 (printed p. 2607): the counter is "captured on-the-fly by a
       GPTi.TCRR read access", and after an overflow it holds GPTi.TLDR in
       autoreload mode or 0 stopped in one-shot mode. */
    CatchUpLocked(now);

    switch (off) {
    /* Table 16-16 (printed p. 2621): TIDR TID_REV [7:0] R, whose reset value the
       manual gives as TI internal data; bits [31:8] Reserved, "Reads return
       0". */
    case kOffTidr:    return 0u;
    /* Table 16-20 (printed p. 2624): TISTAT RESETDONE [0] R, "0x1: Reset
       completed"; bits [31:8] and [7:1] Reserved, "Reads return 0". */
    case kOffTistat:  return 0x1u;
    case kOffTisr:    return tisr_ & kIntMask;
    case kOffTier:    return tier_ & kIntMask;
    case kOffTclr:    return tclr_;
    case kOffTcrr:    return CounterAtLocked(now);
    case kOffTldr:    return tldr_;
    /* Table 16-34 (printed p. 2632): TTGR_VALUE [31:0] - "The value of the
       trigger register. During reads, it always returns 0xFFFFFFFF." */
    case kOffTtgr:    return 0xFFFFFFFFu;
    /* Table 16-36 (printed p. 2633): TWPS is type R and "indicates if a
       Write-Posted is pending"; every W_PEND_* field is R reset 0 and bits
       [31:10] are Reserved, "Reads return 0". */
    case kOffTwps:    return 0u;
    case kOffTmar:    return tmar_;
    case kOffTsicr:   return tsicr_;
    /* §16.2.4.3 (printed p. 2610): TCAR1 and TCAR2 take the counter value only
       on an EVENT_CAPTURE pin edge. §16.2.4.2.1 (printed p. 2610): "By default,
       the GPTi.TPIR, GPTi.TNIR, GPTi.TCVR, GPTi.TOCR, and GPTi.TOWR registers
       and the associated logic are in reset mode (all 0s) and have no action on
       the programming model." */
    case kOffTcar1:   return 0u;
    case kOffTcar2:   return 0u;
    case kOffTpir:    return 0u;
    case kOffTnir:    return 0u;
    case kOffTcvr:    return 0u;
    case kOffTocr:    return 0u;
    case kOffTowr:    return 0u;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Omap3530Gptimer1::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        const int64_t now = NowNs();
        CatchUpLocked(now);

        switch (off) {
        /* §16.2.6.1 (printed p. 2615): the host-writable set is TLDR, TCRR,
           TIER, TISR, TCLR, TIOCP_CFG, TWER, TTGR, TSICR and TMAR, plus TPIR,
           TNIR, TCVR, TOCR and TOWR on GPTIMER1. TIDR, TISTAT, TWPS, TCAR1 and
           TCAR2 are absent from it. */
        case kOffTidr:
        case kOffTistat:
        case kOffTwps:
        case kOffTcar1:
        case kOffTcar2:
            return;
        case kOffTiocp:
            if (value & kTiocpSoftReset) {
                ResetStateLocked();
                break;
            }
            return;
        case kOffTisr:
            tisr_ &= ~(value & kIntMask);
            break;
        case kOffTier:
            tier_ = value & kIntMask;
            LOG(Periph, "[GPTIMER1] TIER <- 0x%X (MAT=%d OVF=%d)\n",
                tier_, (tier_ & kIntMat) ? 1 : 0, (tier_ & kIntOvf) ? 1 : 0);
            break;
        /* Table 16-26 (printed p. 2627): TWER "controls (enable/disable) the
           wake-up feature on specific interrupt events" - MAT_WUP_ENA [0],
           OVF_WUP_ENA [1], TCAR_WUP_ENA [2]. */
        case kOffTwer:
            return;
        case kOffTclr:
            if ((value & kTclrPinFields) != 0) {
                HaltUnsupportedAccess(
                    "WriteWord(TCLR capture / PWM-out pin field)", addr, value);
            }
            ApplyTclrWriteLocked(value & kTclrMask, now);
            return;
        case kOffTcrr:
            LoadCounterLocked(value, now);
            ArmLocked();
            return;
        case kOffTldr:
            tldr_ = value;
            return;
        /* §16.2.4.2 (printed p. 2607): "The GPTi.TCRR register can also be
           loaded with the value held in the timer load register GPTi.TLDR by a
           trigger register (GPTi.TTGR) write access. The GPTi.TCRR loading is
           done regardless of the GPTi.TTGR written value." */
        case kOffTtgr:
            LoadCounterLocked(tldr_, now);
            ArmLocked();
            return;
        case kOffTmar:
            tmar_ = value;
            ArmLocked();
            return;
        case kOffTsicr:
            if (value & kTsicrSft) {
                ResetFunctionalLocked();
            }
            tsicr_ = value & kTsicrPosted;
            break;
        /* §16.2.4.2.1 (printed p. 2610): these registers drive the 1-ms tick
           generation and the overflow interrupt filter, whose reset state is
           all zeros with "no action on the programming model". */
        case kOffTpir:
        case kOffTnir:
        case kOffTcvr:
        case kOffTocr:
        case kOffTowr:
            if (value != 0) {
                HaltUnsupportedAccess(
                    "WriteWord(1-ms tick / overflow-filter register)",
                    addr, value);
            }
            return;
        default:
            HaltUnsupportedAccess("WriteWord", addr, value);
        }
        DriveIrqLineLocked();
    }
}

void Omap3530Gptimer1::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    const int64_t now = NowNs();
    CatchUpLocked(now);
    w.Write("tisr", tisr_);
    w.Write("tier", tier_);
    w.Write("tclr", tclr_);
    w.Write("tldr", tldr_);
    w.Write("tmar", tmar_);
    w.Write("tsicr", tsicr_);
    w.Write<uint32_t>("counter", CounterAtLocked(now));
    w.Write<uint8_t>("running", running_ ? 1u : 0u);
    w.Write<uint8_t>("one_shot_done", one_shot_done_ ? 1u : 0u);
}

void Omap3530Gptimer1::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    r.Read("tisr", tisr_);
    r.Read("tier", tier_);
    r.Read("tclr", tclr_);
    r.Read("tldr", tldr_);
    r.Read("tmar", tmar_);
    r.Read("tsicr", tsicr_);
    uint32_t counter = 0;
    uint8_t  running = 0, one_shot_done = 0;
    r.Read("counter", counter);
    r.Read("running", running);
    r.Read("one_shot_done", one_shot_done);
    tcrr_base_     = counter;
    anchor_ns_     = NowNs();
    folded_ticks_  = 0;
    running_       = (running != 0);
    one_shot_done_ = (one_shot_done != 0);
    ArmLocked();
}

}  /* namespace */

REGISTER_SERVICE(Omap3530Gptimer1);
