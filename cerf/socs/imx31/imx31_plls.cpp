#include "imx31_plls.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../state/state_stream.h"
#include "imx31_clock_input.h"
#include "imx31_id.h"

namespace {

/* MCIMX31RM Table 3-4 CCMR: MPE [3], UPE [9], SPE [8], PRCS [2:1] (01 FPM, 10 CKIH).
   §3.2.1.2: the FPM output "equals 1024*(CKIL frequency)". */
constexpr uint32_t kCcmrPrcsShift  = 1;
constexpr uint32_t kPrcsFpm        = 1u;
constexpr uint32_t kPrcsCkih       = 2u;
constexpr uint64_t kFpmMultiplier  = 1024u;
constexpr uint32_t kEnableBits[]   = {1u << 3, 1u << 9, 1u << 8};
/* Table 3-4 FPME [0]: "This bit defines if the FPM will be enabled. This applies even if it was
   not selected as reference clock source." */
constexpr uint32_t kCcmrFpme       = 1u << 0;
/* Table 3-8 / Table 3-9: a new value in PD [29:26], MFD [25:16], MFI [13:10] or MFN [9:0]
   loses the lock; "after a freq. lock time delay ... the PLL re-locks". */
constexpr uint32_t kFreqFields = 0x3FFF3FFFu;
/* MCIMX31 Technical Data Table 31: frequency lock time at most 398 "Cycles of divided
   reference clock". */
constexpr uint64_t kLockCycles = 398u;
/* Table 3-7 RCSR OSCNT [22:16]: the 32 KHz counter "for the external high speed clock
   oscillator lock time", "Count 1 cycle" at 0000000 to "Count 128 cycles" at 1111111. */
constexpr uint32_t kRcsrOscntShift = 16;
constexpr uint32_t kRcsrOscntMask  = 0x7Fu;

}

bool Imx31Plls::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Imx31;
}

void Imx31Plls::OnReady() {
    clock_ = &emu_.Get<GuestCycleClock>();
    input_ = &emu_.Get<Imx31ClockInput>();
    for (uint32_t p = 0; p < kCount; ++p) {
        lock_events_[p] = clock_->Add([this, p] { OnLock(p); });
    }
    switch_event_ = clock_->Add([this] { OnSwitch(); });
}

uint32_t Imx31Plls::Prcs(uint32_t ccmr) {
    return (ccmr >> kCcmrPrcsShift) & 0x3u;
}

void Imx31Plls::Attach(uint32_t ccmr, const Controls& ctl) {
    prcs_ = static_cast<uint8_t>(Prcs(ccmr));
    ref_.Attach(RefHz(), 1u);
    ckil_.Attach(input_->CkilHz(), 1u);
    clock_->RegisterRateListener([this] {
        ref_.Rescale();
        ckil_.Rescale();
        Rearm();
    });
    Settle(ccmr, ctl);
}

void Imx31Plls::Settle(uint32_t ccmr, const Controls& ctl) {
    for (uint32_t p = 0; p < kCount; ++p) {
        ctl_[p]       = ctl[p];
        on_[p]        = (ccmr & kEnableBits[p]) != 0u ? 1u : 0u;
        relocking_[p] = 0u;
        clock_->Disarm(lock_events_[p]);
    }
    prcs_           = static_cast<uint8_t>(Prcs(ccmr));
    switch_pending_ = 0u;
    clock_->Disarm(switch_event_);
    ref_.SetOscRate(RefHz(), 1u);
}

/* Table 3-4 PRCS: "When a reference clock source is changed, the relevant clock source will be
   automatically enabled, and only after it is available, clock sources will be switched to the
   new source." §3.2.1.3: OSCNT may hold "the delay time that CKIH will be available". */
void Imx31Plls::OnCcmrWrite(uint32_t old, uint32_t value, uint32_t rcsr, const Controls& ctl) {
    const uint32_t want = Prcs(value);
    if (want != Prcs(old) && (old & kEnableBits[0]) != 0u) {
        emu_.Get<Fatal>().Die("Imx31Plls: CCMR 0x%08X changes PRCS while the MCU PLL is enabled",
                              value);
    }
    if (switch_pending_ != 0u && want != switch_prcs_) {
        emu_.Get<Fatal>().Die("Imx31Plls: CCMR 0x%08X changes PRCS while the switch to %u waits "
                              "for its source", value, static_cast<unsigned>(switch_prcs_));
    }
    if (switch_pending_ == 0u && want != prcs_) {
        if (want == kPrcsFpm) {
            emu_.Get<Fatal>().Die("Imx31Plls: CCMR 0x%08X switches the PLL reference to the FPM; "
                                  "the FPM ready time is not modeled", value);
        }
        if (want != kPrcsCkih) {
            emu_.Get<Fatal>().Die("Imx31Plls: CCMR 0x%08X selects the reserved PLL reference %u",
                                  value, want);
        }
        switch_prcs_    = static_cast<uint8_t>(want);
        switch_pending_ = 1u;
        switch_tick_    = ckil_.Now() + ((rcsr >> kRcsrOscntShift) & kRcsrOscntMask) + 1u;
        ckil_.ArmAt(switch_event_, switch_tick_);
    }
    if ((value & kCcmrFpme) == 0u && prcs_ == kPrcsFpm) {
        emu_.Get<Fatal>().Die("Imx31Plls: CCMR 0x%08X disables the FPM while it is the PLL "
                              "reference", value);
    }
    for (uint32_t p = 0; p < kCount; ++p) {
        const uint32_t bit = kEnableBits[p];
        if ((old & bit) != 0u && (value & bit) == 0u) {
            clock_->Disarm(lock_events_[p]);
            relocking_[p] = 0u;
            on_[p]        = 0u;
            ctl_[p]       = ctl[p];
        } else if ((old & bit) == 0u && (value & bit) != 0u) {
            StartRelock(p, ctl[p]);
        }
    }
}

void Imx31Plls::OnControlWrite(uint32_t pll, uint32_t old, uint32_t value, uint32_t ccmr) {
    if (((old ^ value) & kFreqFields) == 0u) return;
    if (relocking_[pll] != 0u) {
        emu_.Get<Fatal>().Die("Imx31Plls: PLL %u control write 0x%08X while it relocks", pll,
                              value);
    }
    if ((ccmr & kEnableBits[pll]) == 0u) {
        ctl_[pll] = value;
        return;
    }
    StartRelock(pll, value);
}

void Imx31Plls::StartRelock(uint32_t pll, uint32_t ctl) {
    lock_ctl_[pll]  = ctl;
    lock_tick_[pll] = ref_.Now() + kLockCycles * (((ctl >> 26) & 0xFu) + 1u);
    relocking_[pll] = 1u;
    ref_.ArmAt(lock_events_[pll], lock_tick_[pll]);
    LOG(SocClkpwr, "Imx31Plls: PLL %u relocks to control 0x%08X\n", pll, ctl);
}

void Imx31Plls::OnLock(uint32_t pll) {
    relocking_[pll] = 0u;
    on_[pll]        = 1u;
    ctl_[pll]       = lock_ctl_[pll];
    Notify();
}

void Imx31Plls::OnSwitch() {
    for (uint32_t p = 0; p < kCount; ++p) {
        if (on_[p] != 0u || relocking_[p] != 0u) {
            emu_.Get<Fatal>().Die("Imx31Plls: PLL %u is enabled when the PLL reference switches "
                                  "to %u; the PLL output across a reference switch is not "
                                  "modeled", p, static_cast<unsigned>(switch_prcs_));
        }
    }
    switch_pending_ = 0u;
    prcs_           = switch_prcs_;
    ref_.SetOscRate(RefHz(), 1u);
    LOG(SocClkpwr, "Imx31Plls: PLL reference switches to %llu Hz\n",
        static_cast<unsigned long long>(RefHz()));
    Notify();
}

void Imx31Plls::Rearm() {
    for (uint32_t p = 0; p < kCount; ++p) {
        if (relocking_[p] != 0u) ref_.ArmAt(lock_events_[p], lock_tick_[p]);
    }
    if (switch_pending_ != 0u) ckil_.ArmAt(switch_event_, switch_tick_);
}

void Imx31Plls::RegisterChangeListener(std::function<void()> fn) {
    listeners_.push_back(std::move(fn));
}

void Imx31Plls::Notify() {
    for (auto& fn : listeners_) fn();
}

/* Figure 3-24: pll_ref_clk is CKIH or the Frequency Pre-Multiplier output, chosen
   by CCMR PRCS (Table 3-4). */
uint64_t Imx31Plls::RefHz() const {
    if (prcs_ == kPrcsCkih) return input_->CkihHz();
    if (prcs_ == kPrcsFpm)  return input_->CkilHz() * kFpmMultiplier;
    emu_.Get<Fatal>().Die("Imx31Plls: the PLL reference select %u is reserved",
                          static_cast<unsigned>(prcs_));
}

/* Eqn 3-1: Fvco = Fref x 2 x (MFI + MFN/MFD) / PD. Field encodings per Table 3-8
   (MPCTL) / Table 3-9 (UPCTL): PD and MFD are stored biased by one, MFI saturates
   up to 5, MFN is a signed 10-bit two's-complement numerator. */
uint64_t Imx31Plls::LockedHz(uint32_t pll) const {
    const uint32_t ctl = ctl_[pll];
    const int64_t  pd  = ((ctl >> 26) & 0xFu) + 1u;
    const int64_t  mfd = ((ctl >> 16) & 0x3FFu) + 1u;
    int64_t mfi = (ctl >> 10) & 0xFu;
    if (mfi < 5) mfi = 5;
    int64_t mfn = static_cast<int64_t>(ctl & 0x3FFu);
    if (mfn & 0x200) mfn -= 0x400;
    const int64_t num = 2 * static_cast<int64_t>(RefHz()) * (mfi * mfd + mfn);
    const int64_t den = mfd * pd;
    if (num <= 0 || num % den != 0) {
        emu_.Get<Fatal>().Die("Imx31Plls: PLL %u control 0x%08X on the %llu Hz reference is not "
                              "a whole number of Hz", pll, ctl,
                              static_cast<unsigned long long>(RefHz()));
    }
    return static_cast<uint64_t>(num / den);
}

uint64_t Imx31Plls::OutputHz(uint32_t pll, uint64_t off_hz) const {
    if (on_[pll] != 0u) return LockedHz(pll);
    if (relocking_[pll] == 0u) return off_hz;
    emu_.Get<Fatal>().Die("Imx31Plls: PLL %u output read during its lock-in after an enable; the "
                          "output before the lock is not modeled", pll);
}

void Imx31Plls::SaveState(StateWriter& w) {
    ref_.Save(w);
    const uint64_t now = ref_.Now();
    std::array<uint64_t, kCount> left{};
    for (uint32_t p = 0; p < kCount; ++p) {
        left[p] = relocking_[p] != 0u ? lock_tick_[p] - now : 0u;
    }
    w.WriteBytes("pll_ctl", ctl_.data(), sizeof(ctl_));
    w.WriteBytes("pll_on", on_.data(), sizeof(on_));
    w.WriteBytes("pll_relocking", relocking_.data(), sizeof(relocking_));
    w.WriteBytes("pll_lock_ctl", lock_ctl_.data(), sizeof(lock_ctl_));
    w.WriteBytes("pll_lock_ticks_left", left.data(), sizeof(left));
    w.Write<uint8_t>("pll_ref_prcs", prcs_);
    w.Write<uint8_t>("pll_ref_switch_pending", switch_pending_);
    w.Write<uint8_t>("pll_ref_switch_prcs", switch_prcs_);
    w.BeginFrame(0u);
    ckil_.Save(w);
    w.EndFrame();
    w.Write<uint64_t>("pll_ref_switch_ticks_left",
                      switch_pending_ != 0u ? switch_tick_ - ckil_.Now() : 0u);
}

void Imx31Plls::RestoreState(StateReader& r) {
    ref_.Restore(r);
    std::array<uint64_t, kCount> left{};
    r.ReadBytes("pll_ctl", ctl_.data(), sizeof(ctl_));
    r.ReadBytes("pll_on", on_.data(), sizeof(on_));
    r.ReadBytes("pll_relocking", relocking_.data(), sizeof(relocking_));
    r.ReadBytes("pll_lock_ctl", lock_ctl_.data(), sizeof(lock_ctl_));
    r.ReadBytes("pll_lock_ticks_left", left.data(), sizeof(left));
    r.Read("pll_ref_prcs", prcs_);
    r.Read("pll_ref_switch_pending", switch_pending_);
    r.Read("pll_ref_switch_prcs", switch_prcs_);
    r.EnterFrame();
    ckil_.Restore(r);
    r.LeaveFrame();
    uint64_t switch_left = 0u;
    r.Read("pll_ref_switch_ticks_left", switch_left);
    const uint64_t now = ref_.Now();
    for (uint32_t p = 0; p < kCount; ++p) {
        lock_tick_[p] = now + left[p];
        clock_->Disarm(lock_events_[p]);
    }
    switch_tick_ = ckil_.Now() + switch_left;
    clock_->Disarm(switch_event_);
}

void Imx31Plls::PostRestore() {
    Rearm();
}

REGISTER_SERVICE(Imx31Plls);
