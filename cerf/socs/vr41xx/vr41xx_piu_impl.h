#pragma once

#include "vr41xx_piu.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../jit/host_request_channel.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "vr41xx_cmu.h"
#include "vr41xx_icu.h"
#include "vr41xx_piu_converter.h"
#include "vr41xx_piu_host_pen.h"
#include "vr41xx_piu_scan_timing.h"
#include "vr41xx_piu_state_table.h"
#include "vr41xx_rtcx_ticks.h"

#include <cstdint>
#include <mutex>
#include <optional>

#include "vr41xx_piu_regs.h"

namespace cerf_vr41xx_piu_detail {


template <const std::string_view& Soc, Vr41xxPiuModel M>
class Vr41xxPiuBase : public Vr41xxPiu {
public:
    using Vr41xxPiu::Vr41xxPiu;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == Soc;
    }

    /* Every PIU register's RTCRST column equals its other-resets column (VR4121 UM
       20.3.1-20.3.10, VR4102 UM 19.3.1-19.3.10). */
    void OnReady() override {
        clock_ = &emu_.Get<GuestCycleClock>();
        scan_.Attach(clock_, &rtcx_);
        event_ = clock_->Add([this] {
            std::lock_guard<std::mutex> lk(mtx_);
            SampleDueLocked();
        });
        rtcx_.Attach([this] {
            std::lock_guard<std::mutex> lk(mtx_);
            if (!rtcx_.Running()) {
                AdvanceLocked();
                if (state_ != kStDisable && state_ != kStStandby && state_ != kStWaitPenTouch) {
                    emu_.Get<Fatal>().Die("VR41xx PIU: SUSPEND entered in PADSTATE %u; the "
                                          "sequencer outside Disable, Standby and WaitPenTouch "
                                          "in Suspend is not modeled", state_);
                }
            }
            ApplyHostPenLocked();
        });
        clock_->RegisterRateListener([this] {
            std::lock_guard<std::mutex> lk(mtx_);
            rtcx_.Rescale();
            ArmLocked();
        });
        host_requests_ = &emu_.Get<HostRequestChannel>();
        host_requests_->RegisterListener([this] {
            std::lock_guard<std::mutex> lk(mtx_);
            ApplyHostPenLocked();
        });
        emu_.Get<Vr41xxCmu>().RegisterClockUser(kCmuMskPiu, "PIU", [this] {
            std::lock_guard<std::mutex> lk(mtx_);
            AdvanceLocked();
            ArmLocked();
            return scan_.Kind() != kScanIdle;
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            std::lock_guard<std::mutex> lk(mtx_);
            ApplyResetLocked();
            ArmLocked();
        });
    }

    uint32_t MmioBase() const override { return M.base; }
    uint32_t MmioSize() const override { return M.size; }
    uint32_t Piu2Base() const override { return M.piu2_base; }
    uint32_t Piu2Size() const override { return M.piu2_size; }

    uint16_t ReadHalf(uint32_t addr) override {
        std::lock_guard<std::mutex> lk(mtx_);
        AdvanceLocked();
        switch (addr - M.base) {
            /* D14 PENSTP "previous touch panel contact state" exists only on the VR4102
               (UM 19.3.1); the VR4121's D15:14 are RFU, "0 is returned after a read"
               (UM 20.3.1). */
            case kOffCnt: {
                uint16_t v = static_cast<uint16_t>((penstc_ ? 0x2000u : 0u) |
                                                   (static_cast<uint32_t>(state_) << 10) |
                                                   (cnt_cfg_ & kCntStored));
                if constexpr (M.has_penstp) {
                    if (pen_prev_) v |= 0x4000u;
                }
                return v;
            }
            case kOffInt:  return intreg_;
            case kOffSivl: return sivl_;
            case kOffStbl: return stbl_;
            case kOffCmd:  return cmd_;
            case kOffAscn: return ascn_;
            case kOffAmsk: return amsk_;
            default: HaltUnsupportedAccess("VR41xx PIU ReadHalf", addr, 0);
        }
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        std::lock_guard<std::mutex> lk(mtx_);
        AdvanceLocked();
        switch (addr - M.base) {
            case kOffCnt: ApplyCntWriteLocked(value); return;
            case kOffInt: AckIntLocked(value); return;
            /* PIUSIVLREG D10:0 SCANINTVAL, PIUSTBLREG D5:0 STABLE, PIUCMDREG D12:0
               (VR4121 UM 20.3.3/20.3.4/20.3.5, VR4102 UM 19.3.3/19.3.4/19.3.5). */
            case kOffSivl: sivl_ = value & 0x07FFu; return;
            case kOffStbl: stbl_ = value & 0x003Fu; return;
            case kOffCmd:  cmd_  = value & 0x1FFFu; return;
            /* PIUASCNREG D1:0 (VR4121 UM 20.3.6, VR4102 UM 19.3.6); PIUAMSKREG D7:0 (VR4121 UM
               20.3.7, VR4102 UM 19.3.7). */
            case kOffAscn:
                if ((value & kAdpsStart) && state_ != kStStandby && state_ != kStDisable) {
                    emu_.Get<Fatal>().Die("VR41xx PIU: PIUASCNREG ADPSSTART set in PADSTATE %u; "
                                          "the port scan out of that state is not modeled", state_);
                }
                ascn_ = value & 0x0003u;
                return;
            case kOffAmsk: amsk_ = value & 0x00FFu; return;
            default: HaltUnsupportedAccess("VR41xx PIU WriteHalf", addr, value);
        }
    }

    uint8_t  ReadByte (uint32_t addr) override { HaltUnsupportedAccess("VR41xx PIU ReadByte", addr, 0); }
    uint32_t ReadWord (uint32_t addr) override { HaltUnsupportedAccess("VR41xx PIU ReadWord", addr, 0); }
    void WriteByte(uint32_t addr, uint8_t  v) override { HaltUnsupportedAccess("VR41xx PIU WriteByte", addr, v); }
    void WriteWord(uint32_t addr, uint32_t v) override { HaltUnsupportedAccess("VR41xx PIU WriteWord", addr, v); }

    uint16_t ReadHalf2(uint32_t off) override {
        std::lock_guard<std::mutex> lk(mtx_);
        uint16_t value = 0;
        if (converter_.ReadBuffer(off, &value)) return value;
        HaltUnsupportedAccess("VR41xx PIU2 ReadHalf", M.piu2_base + off, 0);
    }

    void WriteHalf2(uint32_t off, uint16_t value) override {
        std::lock_guard<std::mutex> lk(mtx_);
        if (converter_.WriteBuffer(off, value)) return;
        HaltUnsupportedAccess("VR41xx PIU2 WriteHalf", M.piu2_base + off, value);
    }

    void SetPen(bool down, uint16_t pos_x, uint16_t pos_y) override {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            host_pen_.Pen(down, pos_x, pos_y);
        }
        host_requests_->Request();
    }

    void SyntheticTap(uint16_t pos_x, uint16_t pos_y) override {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            host_pen_.Tap(pos_x, pos_y);
        }
        host_requests_->Request();
    }

    void SaveState(StateWriter& w) override {
        std::lock_guard<std::mutex> lk(mtx_);
        w.Write("state", state_); w.Write("cnt_cfg", cnt_cfg_); w.Write("intreg", intreg_);
        w.Write("sivl", sivl_); w.Write("stbl", stbl_); w.Write("cmd", cmd_);
        w.Write<uint8_t>("pen_prev", pen_prev_ ? 1 : 0);
        w.Write<uint8_t>("penstc", penstc_ ? 1 : 0);
        w.Write("pos_x", pos_x_); w.Write("pos_y", pos_y_);
        converter_.Save(w);
        w.Write("ascn", ascn_);
        w.Write("amsk", amsk_);
        scan_.Save(w, clock_->Cycles());
    }

    void RestoreState(StateReader& r) override {
        std::lock_guard<std::mutex> lk(mtx_);
        r.Read("state", state_); r.Read("cnt_cfg", cnt_cfg_); r.Read("intreg", intreg_);
        r.Read("sivl", sivl_); r.Read("stbl", stbl_); r.Read("cmd", cmd_);
        uint8_t prev = 0, stc = 0;
        r.Read("pen_prev", prev); r.Read("penstc", stc);
        r.Read("pos_x", pos_x_); r.Read("pos_y", pos_y_);
        converter_.Restore(r);
        r.Read("ascn", ascn_);
        r.Read("amsk", amsk_);
        scan_.Restore(r, clock_->Cycles());
        /* PIUCNTREG D14 PENSTP "Previous touch panel contact state" (R/W) and D13 PENSTC
           "Current touch panel contact state" (VR4102 UM 19.3.1); "when PENCHGINTR is
           cleared to 0, PENSTC indicates the touch panel contact state" (VR4121 UM 20.3.2). */
        pen_cur_  = false;
        pen_prev_ = (prev != 0);
        penstc_   = (stc != 0);
        LatchPenstcLocked();
        if (SamplingLocked()) state_ = (cnt_cfg_ & kAtStop) ? kStWaitPenTouch : kStIntervalNext;
        AbandonScanOutsideStateLocked();
        host_pen_.Clear();
        rtcx_.Rebase();
        next_sample_ = rtcx_.Now();
    }

    void PostRestore() override {
        std::lock_guard<std::mutex> lk(mtx_);
        DriveIcuLocked();
        ArmLocked();
    }

private:

    /* PADATSTART / PADATSTOP (VR4121 UM 20.3.1, VR4102 UM 19.3.1). */
    void PenEdgeLocked(bool down) {
        pen_prev_ = pen_cur_;
        pen_cur_  = down;
        LatchPenstcLocked();
        intreg_ |= kPenChgIntr;
        if (down) {
            if ((cnt_cfg_ & kSeqEn) && (cnt_cfg_ & kAtStart) &&
                state_ == kStWaitPenTouch) {
                state_ = kStPenDataScan;
            }
            if (state_ == kStPenDataScan && scan_.Kind() == kScanIdle && rtcx_.Running()) {
                BeginScanLocked(kScanData, rtcx_.Now(), clock_->Cycles());
                next_sample_ = rtcx_.Now() + IntervalTicksLocked();
            } else if (state_ == kStPenDataScan && scan_.Kind() == kScanIdle) {
                next_sample_ = rtcx_.Now();
            }
        } else if ((cnt_cfg_ & kAtStop) &&
                   (state_ == kStIntervalNext ||
                    (state_ == kStPenDataScan && scan_.Kind() == kScanIdle))) {
            /* "Release & AutoStop = 1" leaves IntervalNextScan, which PenDataScan enters on
               "auto" (VR4121 UM Figure 20-4). */
            state_ = kStWaitPenTouch;
        }
        DriveIcuLocked();
    }

    /* "The PENSTC bit indicates the touch panel contact state at the time when the
       PENCHGINTR bit of PIUINTREG is set to 1 ... PENSTC does not change while PENCHGINTR
       is set to 1" (VR4121 UM 20.3.1). The VR4102's D13 is the "current touch panel
       contact state" with no such hold (UM 19.3.1). */
    void LatchPenstcLocked() {
        if constexpr (M.penstc_latched_by_penchg) {
            if ((intreg_ & kPenChgIntr) == 0) penstc_ = pen_cur_;
        } else {
            penstc_ = pen_cur_;
        }
    }

    /* "when PENCHGINTR is cleared to 0, PENSTC indicates the touch panel contact state"
       (VR4121 UM 20.3.1). The VALID bit of a page buffer "is automatically rendered
       invalid when the page buffer interrupt source (PIUPAGE0INTR or PIUPAGE1INTR) is
       cleared" (VR4121 UM 20.3.9, VR4102 UM 19.3.9). */
    void AckIntLocked(uint16_t value) {
        const uint16_t clr = value & kIntCauses;
        intreg_ &= ~clr;
        if (clr & kPage0Intr) converter_.InvalidatePage(0);
        if (clr & kPage1Intr) converter_.InvalidatePage(1);
        if (clr & kPadAdpIntr) converter_.InvalidateAdBuffer();
        if constexpr (M.penstc_latched_by_penchg) {
            if (clr & kPenChgIntr) penstc_ = pen_cur_;
        }
        DriveIcuLocked();
    }

    void ApplyCntWriteLocked(uint16_t value) {
        /* PADSCANSTART "forced start" / PADSCANSTOP "forced stop" (VR4121 UM 20.3.1,
           VR4102 UM 19.3.1): neither board's driver issues a forced scan. */
        if (value & (kScanStart | kScanStop)) {
            HaltUnsupportedAccess("VR41xx PIU PIUCNTREG forced-scan strobe",
                                  M.base + kOffCnt, value);
        }

        /* PADRST 0->1 is "-" from Disable and "Disable" from every other state; PIUPWR 0->1
           from Disable is "Standby" (VR4121 UM Table 20-2, VR4102 UM Table 19-2). nk.exe
           sub_9F0B61DC stores PADRST|PIUPWR in one halfword (MEMORY[0xAB000122] = 3), then
           spins for PADSTATE == Standby. */
        if (value & kPadRst) ApplyResetLocked();

        const uint16_t old = cnt_cfg_;
        cnt_cfg_ = value & kCntStored;
        const uint16_t next = StateAfterCntWrite(state_, old, cnt_cfg_, ascn_);
        if (next == kStAdPortScan && ((old ^ cnt_cfg_) & 0x0018u) != 0u) {
            emu_.Get<Fatal>().Die("VR41xx PIU: PIUCNTREG 0x%04X starts an ADPortScan and changes "
                                  "PIUMODE in one store; not modeled", value);
        }
        state_ = next;

        AbandonScanOutsideStateLocked();
        if (state_ == kStAdPortScan && scan_.Kind() == kScanIdle) {
            BeginScanLocked(kScanAdPort, rtcx_.Now(), clock_->Cycles());
            ArmLocked();
        }

        /* PADATSTART "1: Auto start during touch state" (VR4121 UM 20.3.1, VR4102 UM
           19.3.1). */
        if (pen_cur_ && (cnt_cfg_ & kSeqEn) && (cnt_cfg_ & kAtStart) &&
            state_ == kStWaitPenTouch) {
            state_ = kStPenDataScan;
            BeginScanLocked(kScanData, rtcx_.Now(), clock_->Cycles());
            next_sample_ = rtcx_.Now() + IntervalTicksLocked();
            ArmLocked();
        } else if (state_ == kStCmdScan) {
            /* A command scan fetches "one port only" per PIUSEQEN kick and CmdScan has no
               self-loop (VR4121 UM 20.2 (4), Figure 20-4; VR4102 UM 19.2, Figure 19-4);
               touch.dll sub_15A0E24 re-arms "PIUCNTREG |= PIUSEQEN" after every sample. */
            BeginScanLocked(kScanCmd, rtcx_.Now(), clock_->Cycles());
            ArmLocked();
        }
    }

    void BeginScanLocked(uint16_t kind, uint64_t start_tick, uint64_t start_cycle) {
        emu_.Get<Vr41xxCmu>().RequireTclock(kCmuMskPiu, "PIU scan start");
        scan_.Begin(kind, stbl_, start_tick, start_cycle);
    }

    void CompleteScanLocked() {
        const uint16_t kind = scan_.Take();
        if (kind == kScanData) {
            const int page = converter_.ConvertCoordinates(pos_x_, pos_y_);
            /* PIUINTREG OVP "1: Valid data older than page 1 buffer data is retained / 0: Valid
               data older than page 0 buffer data is retained" (VR4121 UM 20.3.2, VR4102 UM
               19.3.2). */
            intreg_ |= (page == 0) ? kPage0Intr : kPage1Intr;
            intreg_ = (intreg_ & ~kOvp) | ((page == 1) ? kOvp : 0u);
            state_ = (!pen_cur_ && (cnt_cfg_ & kAtStop)) ? kStWaitPenTouch : kStIntervalNext;
            if (synthetic_hold_ != 0 && --synthetic_hold_ == 0) PenEdgeLocked(false);
        } else if (kind == kScanCmd) {
            if (converter_.ConvertCommand(cmd_, pos_x_, pos_y_)) intreg_ |= kPadCmdIntr;
        } else {
            if (converter_.ScanAdPorts(ascn_, amsk_)) intreg_ |= kPadAdpIntr;
            ascn_ &= ~kAdpsStart;
            state_ = kStStandby;
        }
        DriveIcuLocked();
    }

    void AbandonScanOutsideStateLocked() {
        if (scan_.Kind() != kScanIdle && state_ != kScanState[scan_.Kind()]) scan_.Drop();
    }

    /* The ICU's PIUINTREG (0x0B000082) carries the PIU's interrupt causes and raises
       SYSINT1REG PIUINTR when unmasked (VR4121 UM 15.1, VR4102 UM 14.1). */
    void DriveIcuLocked() {
        emu_.Get<Vr41xxIcu>().SetPiuSource(intreg_ & kIntCauses);
    }

    /* "Interval = SCANINTVAL(10:0) x 30 us" (VR4121 UM 20.3.3, VR4102 UM 19.3.3). */
    uint64_t IntervalTicksLocked() const {
        const uint64_t ticks = sivl_ & 0x07FFu;
        if (ticks == 0u) {
            emu_.Get<Fatal>().Die("VR41xx PIU: sampling with PIUSIVLREG SCANINTVAL 0; the "
                                  "per-pair conversion time is not modeled");
        }
        return ticks;
    }

    bool SamplingLocked() const { return state_ == kStPenDataScan || state_ == kStIntervalNext; }

    bool IntervalScanStartedLocked() {
        return SamplingLocked() && rtcx_.Running() && rtcx_.Now() >= next_sample_;
    }

    void AdvanceLocked() {
        for (;;) {
            const bool start = IntervalScanStartedLocked();
            if (scan_.Kind() != kScanIdle && clock_->Cycles() >= scan_.ReadyAt() &&
                (!start || scan_.ReadyAt() <= rtcx_.CycleOf(next_sample_))) {
                CompleteScanLocked();
                continue;
            }
            if (!start) return;
            if (!pen_cur_) {
                emu_.Get<Fatal>().Die("VR41xx PIU: data scan with the pen released and PADATSTOP "
                                      "0; the released panel's A/D values are not modeled");
            }
            state_ = kStPenDataScan;
            BeginScanLocked(kScanData, next_sample_, rtcx_.CycleOf(next_sample_));
            next_sample_ += IntervalTicksLocked();
        }
    }

    void SampleDueLocked() {
        AdvanceLocked();
        ArmLocked();
    }

    void ArmLocked() {
        if (!rtcx_.Running() || (scan_.Kind() == kScanIdle && !SamplingLocked())) {
            clock_->Disarm(event_);
            return;
        }
        clock_->Arm(event_, scan_.Kind() != kScanIdle
                                ? scan_.ReadyAt()
                                : scan_.ReadyCycle(kScanData, stbl_, next_sample_,
                                                   rtcx_.CycleOf(next_sample_)));
    }

    void ApplyHostPenLocked() {
        if constexpr (!M.pen_detect_in_suspend) {
            if (!rtcx_.Running()) {
                ArmLocked();
                return;
            }
        }
        AdvanceLocked();
        if (const std::optional<Vr41xxPiuPenPoint> p = host_pen_.TakePen()) {
            pos_x_          = p->x;
            pos_y_          = p->y;
            synthetic_hold_ = 0;
            if (p->down != pen_cur_) PenEdgeLocked(p->down);
        }
        if (const std::optional<Vr41xxPiuPenPoint> t = host_pen_.TakeTap(); t && !pen_cur_) {
            pos_x_          = t->x;
            pos_y_          = t->y;
            synthetic_hold_ = kSyntheticHoldScans;
            PenEdgeLocked(true);
        }
        ArmLocked();
    }

    /* PENSTP "Previous touch panel contact state", R/W, both reset rows 0 (VR4102 UM
       19.3.1). "When PENCHGINTR is cleared to 0, PENSTC indicates the touch panel contact
       state" (VR4121 UM 20.3.1). */
    void ApplyResetLocked() {
        state_     = kStDisable;
        cnt_cfg_   = 0;
        intreg_    = 0;
        sivl_      = M.sivl_power_on;
        stbl_      = kStblPowerOn;
        cmd_       = kCmdPowerOn;
        pen_prev_  = false;
        penstc_    = pen_cur_;
        converter_.Reset();
        ascn_      = 0;
        amsk_      = 0;
        scan_.Drop();
        DriveIcuLocked();
    }

    mutable std::mutex mtx_;

    uint16_t state_    = kStDisable;
    uint16_t cnt_cfg_  = 0;
    uint16_t intreg_   = 0;
    uint16_t sivl_     = M.sivl_power_on;
    uint16_t stbl_     = kStblPowerOn;
    uint16_t cmd_      = kCmdPowerOn;

    bool     pen_cur_  = false;
    bool     pen_prev_ = false;
    bool     penstc_   = false;
    uint16_t pos_x_    = 0;
    uint16_t pos_y_    = 0;
    uint16_t synthetic_hold_ = 0;

    Vr41xxPiuConverter converter_{emu_};
    uint16_t ascn_ = 0;
    uint16_t amsk_ = 0;

    static constexpr uint16_t kScanIdle   = Vr41xxPiuScanTiming::kIdle;
    static constexpr uint16_t kScanData   = Vr41xxPiuScanTiming::kData;
    static constexpr uint16_t kScanCmd    = Vr41xxPiuScanTiming::kCmd;
    static constexpr uint16_t kScanAdPort = Vr41xxPiuScanTiming::kAdPort;
    static constexpr uint16_t kScanState[] = {kStDisable, kStPenDataScan, kStCmdScan,
                                              kStAdPortScan};
    Vr41xxPiuScanTiming scan_{emu_};

    GuestCycleClock*        clock_       = nullptr;
    GuestCycleClock::Event* event_       = nullptr;
    HostRequestChannel*     host_requests_ = nullptr;
    Vr41xxRtcxTicks         rtcx_{emu_, Vr41xxRtcxDomain::Peripheral};
    uint64_t                next_sample_ = 0;
    Vr41xxPiuHostPen        host_pen_;
};

}  /* namespace cerf_vr41xx_piu_detail */
