#include "imx51_dpll.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "imx51_ccm.h"
#include "imx51_clock_input.h"
#include "imx51_id.h"

#include <cstdint>

namespace {

/* MCIMX51RM Table 22-1 register summary and Table 22-2 DP_CTL. */
constexpr uint32_t kDpCtlOff    = 0x000u;
constexpr uint32_t kDpConfigOff = 0x004u;
constexpr uint32_t kDpOpOff     = 0x008u;
constexpr uint32_t kDpMfdOff    = 0x00Cu;
constexpr uint32_t kDpMfnOff    = 0x010u;
constexpr uint32_t kDpHfsOpOff  = 0x01Cu;
constexpr uint32_t kDpHfsMfdOff = 0x020u;
constexpr uint32_t kDpTogcOff   = 0x028u;
constexpr uint32_t kDpDestatOff = 0x02Cu;

/* Table 22-1: the fields each register stores. */
constexpr uint32_t kFieldMasks[] = {
    0x00003F7Eu, 0x0000000Fu, 0x000000FFu, 0x07FFFFFFu, 0x07FFFFFFu, 0x07FFFFFFu,
    0x07FFFFFFu, 0x000000FFu, 0x07FFFFFFu, 0x07FFFFFFu, 0x0003FFFFu,
};

/* Table 22-10 TOG_DIS [17], TOG_EN [16]; Table 22-11: the desense logic runs when TOG_EN
   is set and TOG_DIS is clear. */
constexpr uint32_t kTogcDis = 1u << 17;
constexpr uint32_t kTogcEn  = 1u << 16;

/* Figure 22-12: DP_DESTAT reset value; Table 22-12 TOG_SEL 0: desense logic inactive. */
constexpr uint32_t kDestatInactive = 0x00020000u;

constexpr uint32_t kCtlLrf        = 1u << 0;
constexpr uint32_t kCtlPlm        = 1u << 2;
constexpr uint32_t kCtlRcp        = 1u << 3;
constexpr uint32_t kCtlRst        = 1u << 4;
constexpr uint32_t kCtlUpen       = 1u << 5;
constexpr uint32_t kCtlPre        = 1u << 6;
constexpr uint32_t kCtlRefSelShift = 8;
constexpr uint32_t kCtlRefDiv     = 1u << 10;
constexpr uint32_t kCtlAde        = 1u << 11;
constexpr uint32_t kCtlDpdck02En  = 1u << 12;
constexpr uint32_t kCtlMulCtrl    = 1u << 13;

constexpr uint32_t kCfgLdreq  = 1u << 0;
constexpr uint32_t kCfgAren   = 1u << 1;
constexpr uint32_t kCfgSjcCe  = 1u << 2;
constexpr uint32_t kCfgBistCe = 1u << 3;

/* Table 22-2 REF_CLK_SEL: clk 2 is COSC (internal oscillator), clk 3 is FPM. */
constexpr uint32_t kRefSelCosc = 2u;

constexpr uint32_t kMfnMask = 0x07FFFFFFu;
constexpr uint32_t kMfdMask = 0x07FFFFFFu;

/* Figure 22-15 and its NOTE: a register write asserts crstrt one reference clock later, the
   port updates one clock after that and crstrt releases four clocks later; setting RST
   asserts crstrt at once. */
constexpr uint64_t kAutoRestartClocks = 6u;
constexpr uint64_t kRstRestartClocks  = 5u;
/* MCIMX51RM p.21-7 and Figure 21-4: "The DPLL starts after three reference clock periods". */
constexpr uint64_t kStartClocks = 3u;
/* IMX51CEC Table 48 note 4: at most 398 cycles of divided reference clock after a full reset;
   MCIMX51RM p.21-7: a CRSTRT-only (partial) restart reduces the lock-in by 128 of them. */
constexpr uint64_t kLockInFull    = 398u;
constexpr uint64_t kLockInPartial = 398u - 128u;

}

bool Imx51Dpll::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Imx51;
}

void Imx51Dpll::OnReady() {
    clock_      = &emu_.Get<GuestCycleClock>();
    lock_event_ = clock_->Add([this] { OnLock(); });
    ref_.Attach(emu_.Get<Imx51ClockInput>().OscHz(), 1u);
    clock_->RegisterRateListener([this] {
        ref_.Rescale();
        if (lock_ == Lock::kRelocking) ref_.ArmAt(lock_event_, lock_tick_);
    });
    ResetRegisters();
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        ResetRegisters();
    });
    emu_.Get<PeripheralDispatcher>().Register(this);
}

/* Figure 22-3: DP_CONFIG resets with AREN set. MCIMX51RM Table 54-10: every reset
   type asserts system_early_rst_b, which resets the CCM and the PLL-IPs. */
void Imx51Dpll::ResetRegisters() {
    regs_.fill(0u);
    regs_[kDpConfigOff >> 2] = kCfgAren;
    output_known_ = false;
    output_hz_    = 0u;
    lock_         = Lock::kOff;
    target_hz_    = 0u;
    clock_->Disarm(lock_event_);
}

/* Table 22-2 LRF: a sticky bit, reset 0; a DP_CTL, DP_OP, DP_MFD, DP_HFS_OP or DP_HFS_MFD
   write, a hard reset or a DPLL enable breaks the lock. HFSM 0: LFS mode. */
uint32_t Imx51Dpll::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off == kDpDestatOff) return kDestatInactive;
    if ((off & 0x3u) != 0u || off > kDpTogcOff) HaltUnsupportedAccess("ReadWord", addr, 0);
    uint32_t v = regs_[off >> 2];
    if (off == kDpCtlOff) {
        if (lock_ == Lock::kBroken) {
            emu_.Get<Fatal>().Die("Imx51Dpll %08X: DP_CTL read after a write broke the lock "
                                  "with no restart; whether LRF sets again is not modeled",
                                  MmioBase());
        }
        if (lock_ == Lock::kLocked) v |= kCtlLrf;
    }
    return v;
}

/* Table 22-3 AREN: a write to DP_CTL, DP_OP or DP_MFD issues a restart; otherwise
   DP_CTL RST restarts. */
void Imx51Dpll::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off == kDpDestatOff) return;
    if ((off & 0x3u) != 0u || off > kDpTogcOff) HaltUnsupportedAccess("WriteWord", addr, value);
    if (off == kDpCtlOff &&
        (value & (kCtlMulCtrl | kCtlPre | kCtlAde | kCtlRcp | kCtlPlm)) != 0u) {
        emu_.Get<Fatal>().Die("Imx51Dpll %08X: DP_CTL write 0x%08X sets MUL_CTRL, PRE, ADE, RCP "
                              "or PLM", MmioBase(), value);
    }
    if (off == kDpConfigOff && (value & (kCfgBistCe | kCfgSjcCe)) != 0u) {
        emu_.Get<Fatal>().Die("Imx51Dpll %08X: DP_CONFIG write 0x%08X sets BIST_CE or SJC_CE",
                              MmioBase(), value);
    }
    if (off == kDpConfigOff && (value & kCfgLdreq) != 0u) {
        emu_.Get<Fatal>().Die("Imx51Dpll %08X: DP_CONFIG write 0x%08X sets LDREQ; the MFN load "
                              "handshake is not modeled", MmioBase(), value);
    }
    if (off == kDpTogcOff && (value & kTogcEn) != 0u && (value & kTogcDis) == 0u) {
        emu_.Get<Fatal>().Die("Imx51Dpll %08X: DP_MFN_TOGC 0x%08X turns the desense logic on",
                              MmioBase(), value);
    }
    const bool hfs    = off == kDpHfsOpOff || off == kDpHfsMfdOff;
    const bool breaks = off == kDpCtlOff || off == kDpOpOff || off == kDpMfdOff || hfs;
    if (breaks && lock_ == Lock::kRelocking) {
        emu_.Get<Fatal>().Die("Imx51Dpll %08X: write 0x%08X to +0x%03X while the DPLL relocks",
                              MmioBase(), value, off);
    }
    const uint32_t old_ctl = regs_[kDpCtlOff >> 2];
    regs_[off >> 2] = value & kFieldMasks[off >> 2];
    if (!breaks) return;
    const bool aren   = (regs_[kDpConfigOff >> 2] & kCfgAren) != 0u;
    const bool by_rst = off == kDpCtlOff && (value & kCtlRst) != 0u;
    if (by_rst || (aren && !hfs)) {
        Restart((old_ctl & kCtlUpen) != 0u, by_rst);
        return;
    }
    if (((old_ctl ^ regs_[kDpCtlOff >> 2]) & kCtlUpen) != 0u) {
        emu_.Get<Fatal>().Die("Imx51Dpll %08X: DP_CTL write 0x%08X changes UPEN with no "
                              "restart", MmioBase(), value);
    }
    if (lock_ == Lock::kLocked) lock_ = Lock::kBroken;
}

void Imx51Dpll::Restart(bool was_enabled, bool by_rst) {
    const uint32_t ctl = regs_[kDpCtlOff >> 2];
    if ((ctl & kCtlUpen) == 0u) {
        clock_->Disarm(lock_event_);
        lock_ = Lock::kOff;
        SetOutput(0u);
        return;
    }
    const uint64_t pdf     = (regs_[kDpOpOff >> 2] & 0xFu) + 1u;
    const uint64_t lock_in = was_enabled ? kLockInPartial : kLockInFull;
    const uint64_t clocks  = (by_rst ? kRstRestartClocks : kAutoRestartClocks) + kStartClocks +
                             lock_in * pdf;
    target_hz_ = ComputeHz();
    lock_      = Lock::kRelocking;
    lock_tick_ = ref_.Now() + clocks * ((ctl & kCtlRefDiv) != 0u ? 2u : 1u);
    ref_.ArmAt(lock_event_, lock_tick_);
    LOG(SocClkpwr, "Imx51Dpll %08X: restart, locks at %llu Hz in %llu reference clocks\n",
        MmioBase(), static_cast<unsigned long long>(target_hz_),
        static_cast<unsigned long long>(clocks));
    emu_.Get<Imx51Ccm>().ApplyRates();
}

void Imx51Dpll::OnLock() {
    lock_         = Lock::kLocked;
    output_known_ = true;
    output_hz_    = target_hz_;
    LOG(SocClkpwr, "Imx51Dpll %08X: locked at %llu Hz\n", MmioBase(),
        static_cast<unsigned long long>(output_hz_));
    emu_.Get<Imx51Ccm>().ApplyRates();
}

void Imx51Dpll::SetOutput(uint64_t hz) {
    const bool changed = !output_known_ || hz != output_hz_;
    output_known_ = true;
    output_hz_    = hz;
    LOG(SocClkpwr, "Imx51Dpll %08X: output %llu Hz\n", MmioBase(),
        static_cast<unsigned long long>(hz));
    if (changed) emu_.Get<Imx51Ccm>().ApplyRates();
}

uint64_t Imx51Dpll::ReferenceHz() const {
    const uint32_t ctl = regs_[kDpCtlOff >> 2];
    const uint32_t sel = (ctl >> kCtlRefSelShift) & 0x3u;
    if (sel != kRefSelCosc) {
        emu_.Get<Fatal>().Die("Imx51Dpll %08X: DP_CTL 0x%08X selects reference clock %u, "
                              "only COSC is modeled", MmioBase(), ctl, sel);
    }
    const uint64_t osc = emu_.Get<Imx51ClockInput>().OscHz();
    if ((ctl & kCtlRefDiv) == 0u) return osc;
    if (osc % 2u != 0u) {
        emu_.Get<Fatal>().Die("Imx51Dpll %08X: REF_CLK_DIV halves a %llu Hz reference to a "
                              "fraction of a Hz", MmioBase(), static_cast<unsigned long long>(osc));
    }
    return osc / 2u;
}

/* Eqn 22-1 with MF = MFI + MFN / (MFD + 1); Table 22-4 MFI below 5 reads as 5.
   Linux i.MX PLLv2 clock driver __clk_pllv2_recalc_rate: 2 x the reference,
   doubled again with DPDCK0_2_EN, MFN sign-extended from bit 26. */
uint64_t Imx51Dpll::ComputeHz() const {
    const uint32_t ctl = regs_[kDpCtlOff >> 2];
    const uint32_t op  = regs_[kDpOpOff >> 2];
    int64_t mfi = (op >> 4) & 0xFu;
    if (mfi < 5) mfi = 5;
    const int64_t pdf = static_cast<int64_t>(op & 0xFu) + 1;
    const int64_t mfd = static_cast<int64_t>(regs_[kDpMfdOff >> 2] & kMfdMask) + 1;
    int64_t mfn = static_cast<int64_t>(regs_[kDpMfnOff >> 2] & kMfnMask);
    if ((mfn & 0x04000000) != 0) mfn -= 0x08000000;
    const int64_t ref = static_cast<int64_t>(ReferenceHz()) *
                        ((ctl & kCtlDpdck02En) != 0u ? 4 : 2);
    const int64_t num = ref * (mfi * mfd + mfn);
    const int64_t den = mfd * pdf;
    if (num <= 0 || num % den != 0) {
        emu_.Get<Fatal>().Die("Imx51Dpll %08X: DP_OP 0x%08X DP_MFD 0x%08X DP_MFN 0x%08X on the "
                              "%llu Hz reference is not a whole number of Hz", MmioBase(), op,
                              regs_[kDpMfdOff >> 2], regs_[kDpMfnOff >> 2],
                              static_cast<unsigned long long>(ReferenceHz()));
    }
    return static_cast<uint64_t>(num / den);
}

uint64_t Imx51Dpll::OutputHz() const {
    if (lock_ == Lock::kRelocking) {
        emu_.Get<Fatal>().Die("Imx51Dpll %08X: output read while the DPLL relocks after a "
                              "restart; its output during lock-in is not modeled", MmioBase());
    }
    if (!output_known_) {
        emu_.Get<Fatal>().Die("Imx51Dpll %08X: output read before the guest restarted "
                              "the DPLL; the boot ROM configuration is not modeled",
                              MmioBase());
    }
    return output_hz_;
}

void Imx51Dpll::SaveState(StateWriter& w) {
    w.WriteBytes("regs", regs_.data(), sizeof(regs_));
    w.Write<uint8_t>("output_known", output_known_ ? 1u : 0u);
    w.Write<uint64_t>("output_hz", output_hz_);
    ref_.Save(w);
    w.Write<uint8_t>("lock_state", static_cast<uint8_t>(lock_));
    w.Write<uint64_t>("lock_target_hz", target_hz_);
    w.Write<uint64_t>("lock_ticks_left",
                      lock_ == Lock::kRelocking ? lock_tick_ - ref_.Now() : 0u);
}

void Imx51Dpll::RestoreState(StateReader& r) {
    r.ReadBytes("regs", regs_.data(), sizeof(regs_));
    uint8_t known = 0;
    r.Read("output_known", known);
    output_known_ = known != 0u;
    r.Read("output_hz", output_hz_);
    ref_.Restore(r);
    uint8_t  lock = 0;
    uint64_t left = 0;
    r.Read("lock_state", lock);
    r.Read("lock_target_hz", target_hz_);
    r.Read("lock_ticks_left", left);
    lock_      = static_cast<Lock>(lock);
    lock_tick_ = ref_.Now() + left;
    clock_->Disarm(lock_event_);
}

void Imx51Dpll::PostRestore() {
    if (lock_ == Lock::kRelocking) ref_.ArmAt(lock_event_, lock_tick_);
}
