#include "vr41xx_kiu.h"

#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "vr41xx_icu.h"
#include "vr41xx_kiu_regs.h"

#include <chrono>
#include <cstdint>

using namespace cerf_vr41xx_kiu_regs;

void Vr41xxKiu::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        std::lock_guard<std::mutex> lk(mtx_);
        ApplyResetLocked();
    });
    worker_ = std::thread([this] { WorkerLoop(); });
}

/* KIURST "forcibly reset the KIU registers" (VR4111 UM 22.2.7 p469, VR4121 UM 22.2.7 p521;
   VR4102 UM 21.2.7 p432 states it without the KIUGPEN exemption). */
void Vr41xxKiu::ApplyResetLocked() {
    scanrep_ = kScanRepPowerOn;
    causes_  = 0;
    sstat_   = kSStatStopped;
    wintvl_  = 0;
    wks_     = kWksReset;
    scanline_ = 0;
    zero_scans_ = 0;
    data_unread_ = false;
    scan_in_flight_ = false;
    stop_after_scan_ = false;
    scanstart_set_while_running_ = false;
    scanstp_set_in_waitkeyin_ = false;
    for (uint16_t& w : matrix_) w = 0;
    PublishCausesLocked();
}

bool Vr41xxKiu::EnabledLocked() const { return (scanrep_ & kKeyen) != 0; }

/* SCANLINE selects the scan-line count (VR4111 UM 22.2.9 p472, VR4102 UM 21.2.9 p434,
   VR4121 UM 22.2.9 p524). */
uint32_t Vr41xxKiu::ScanLinesLocked() {
    switch (scanline_ & kScanLineMask) {
        case 0x0000u: return 12u;
        case 0x0001u: return 10u;
        case 0x0002u: return 8u;
        default:      HaltUnsupportedAccess("KIU scan with SCANLINE = 11", kBase + kOffScanLine,
                                            scanline_);
    }
}

uint32_t Vr41xxKiu::ScanRegsLocked() { return ScanLinesLocked() / 2u; }

/* A KPORT touch is "When any of KPORT[7..0] pins is '1'" (VR4111 UM Figure 22-3 p473 glossary;
   VR4121 UM Figure 22-5 p525 defines the same condition over KPORT(7:0)). VR4102 UM 21.2.2 p426
   states the arc without a figure - "the key scan operation automatically starts after key
   contact is detected". On the scan lines SCANLINE selects (22.2.9 p472 / p434 / p524). */
bool Vr41xxKiu::AnyKeyDownLocked() {
    const uint32_t regs = ScanRegsLocked();
    for (uint32_t i = 0; i < regs; ++i)
        if (held_[i]) return true;
    return false;
}

/* "The data registers KIUDAT00 through KIUDAT05 overwrite the following scan data"
   (VR4111 UM 22.2.1 p461, VR4121 UM 22.2.1 p513); each holds "the data from one scan
   operation" (VR4102 UM 21.2.1 p424). A scan line the SCANLINE setting excludes is never
   pulsed, so its KIUDATn keeps its content (22.2.9 p472). */
void Vr41xxKiu::LatchScanLocked() {
    const uint32_t regs = ScanRegsLocked();
    for (uint32_t i = 0; i < regs; ++i) matrix_[i] = held_[i];
}

/* One set of key scan data walks every KSCAN pin, each costing T1CNT + T2CNT + T3CNT, and the
   sets are separated by the KIUWKI interval (VR4111 UM 22.2.4 p466 / 22.2.5 p467 figures,
   VR4102 UM p429 / p430, VR4121 UM Figure 22-2 p519 and Figure 22-3 p520). */
uint32_t Vr41xxKiu::ScanPeriodUsLocked() {
    const uint32_t t1 = wks_ & kCntBits;
    const uint32_t t2 = (wks_ >> kT2CntShift) & kCntBits;
    const uint32_t t3 = (wks_ >> kT3CntShift) & kCntBits;
    return ScanLinesLocked() * (t1 + t2 + t3 + 3u) * kTimeUnitUs;
}

/* STPREP[5:0] "key scan sequencer stop count setting", 000001 one time .. 111111 63 times
   (VR4111 UM 22.2.2 p463, VR4102 UM 21.2.2 p425, VR4121 UM 22.2.2 p514); the 000000 row is
   per-chip and comes from the model. */
uint32_t Vr41xxKiu::StpRepCountLocked() const {
    const uint32_t stprep = (scanrep_ >> kStpRepShift) & kStpRepBits;
    return stprep != 0 ? stprep : Model().stprep_zero_count;
}

/* SCANINT on a key touch in the touch-wait state or when a scan starts after SCANSTART
   (VR4111 UM 22.2.6 p468, VR4102 UM 21.2.6 p431, VR4121 UM 22.2.6 p520). SCANSTART clears on
   entry to scanning "except if the SCANSTART bit was set to 1 during the interval or scanning
   mode" (VR4111 UM Fig 22-3 p473 Note 6, VR4121 UM Fig 22-5 p525; none on VR4102 p425/p426). */
void Vr41xxKiu::BeginScanLocked() {
    sstat_ = kSStatScanning;
    scan_in_flight_ = false;
    if (Model().scanstart_auto_clear && !scanstart_set_while_running_)
        scanrep_ &= static_cast<uint16_t>(~kScanStart);
    causes_ |= kScanInt;
}

/* Waitkeyin leaves for scanning on "(set ATSCAN = 1 and KPORT touch)" (VR4111 UM Figure 22-3
   p473, VR4121 UM Figure 22-5 p525); VR4102 UM 21.2.2 p426 states the same arc in prose. */
void Vr41xxKiu::EnterWaitKeyInLocked() {
    sstat_ = kSStatWaitKeyIn;
    if ((scanrep_ & kAtScan) && AnyKeyDownLocked()) BeginScanLocked();
}

void Vr41xxKiu::ReevaluateWaitKeyInLocked() {
    if (EnabledLocked() && sstat_ <= kSStatWaitKeyIn) EnterWaitKeyInLocked();
}

/* SCANSTP -> waitkeyin, bit "becomes 0 automatically" (VR4111 UM Figure 22-3 p473 Notes 4/5,
   VR4121 UM Figure 22-5 p525). VR4102 UM 21.2.2 p426 gives the stop and its deferral, not the
   clear; the clear is ROM-grounded - nec_mobilepro_700_ce2 keybddr.dll sub_15B1A00 @0x15B2000
   sets it via sub_15B4858, and only sub_15B13BC @0x15B1438 clears it, at init. */
void Vr41xxKiu::ClearScanStpLocked() {
    scanrep_ &= static_cast<uint16_t>(~kScanStp);
    EnterWaitKeyInLocked();
}

/* KDATRDY on scan completion (VR4111 UM 22.2.6 p468, VR4102 UM 21.2.6 p431, VR4121 UM 22.2.6
   p520). Scan end reaches interval, "waiting for the start of the next key scan" (VR4102 UM
   21.2.3 p428; VR4111 UM Fig 22-3 p473, VR4121 UM Fig 22-5 p525). */
void Vr41xxKiu::CompleteScanLocked() {
    LatchScanLocked();
    data_unread_ = true;
    causes_ |= kKDatRdy;

    if (AnyKeyDownLocked()) zero_scans_ = 0;
    else                    ++zero_scans_;

    if (stop_after_scan_) {
        stop_after_scan_ = false;
        sstat_ = kSStatStopped;
        return;
    }
    /* SCANSTP set while the sequencer waited for a key returns to waitkeyin after "scanning a
       set of data", and Note 3 states no automatic clear where Notes 4 and 5 both do; D3 is R/W
       with reset 0 (VR4111 UM Fig 22-3 p473 with 22.2.2 p463, VR4121 UM Fig 22-5 p525 with
       22.2.2 p514, VR4102 UM 21.2.2 p425 with the stop and its deferral on p426). */
    if (scanrep_ & kScanStp) {
        if (scanstp_set_in_waitkeyin_) EnterWaitKeyInLocked();
        else                           ClearScanStpLocked();
        return;
    }
    /* "(set ATSTP = 1 and stop repeat number full)" draws scanning -> waitkeyin (VR4111 UM
       Fig 22-3 p473, VR4121 UM Fig 22-5 p525). VR4102 UM 21.2.2 p426 has the sequencer "stop
       automatically" without naming a state; 21.2.3 p428 defines "Stopped" as "the state where
       the sequencer is disabled" and "Wait Key in" as the enabled-with-ATSCAN wait state. */
    if (scanrep_ & kAtStp) {
        if (zero_scans_ >= StpRepCountLocked()) {
            zero_scans_ = 0;
            EnterWaitKeyInLocked();
            return;
        }
    }
    sstat_ = kSStatInterval;
}

/* KEYEN "1: Enable / 0: Prohibit" and SSTAT 11 Scanning / 10 Interval / 01 WaitKeyIn /
   00 Stopped are on all three chips (VR4111 UM 22.2.2 p463 + 22.2.3 p465, VR4102 UM 21.2.2
   p425 + 21.2.3 p427, VR4121 UM 22.2.2 p514 + 22.2.3 p516); the SCANSTART auto-clear, the
   SCANLINE = 11 interlock and Note 1's stop-after-scan are per-chip and gated on the model. */
void Vr41xxKiu::ApplyScanRepLocked() {
    /* Note 6 exempts SCANSTART from the automatic clear when the bit "was set to 1 during the
       interval or scanning mode" (VR4111 UM Fig 22-3 p473, VR4121 UM Fig 22-5 p525). */
    scanstart_set_while_running_ = (scanrep_ & kScanStart) != 0 &&
                                   (sstat_ == kSStatInterval || sstat_ == kSStatScanning);
    scanstp_set_in_waitkeyin_ = (scanrep_ & kScanStp) != 0 && sstat_ <= kSStatWaitKeyIn;
    const uint16_t state_at_write = sstat_;

    if ((scanrep_ & kAtStp) && StpRepCountLocked() == 0)
        HaltUnsupportedAccess("KIU ATSTP with an RFU STPREP count", kBase + kOffScanRep,
                              scanrep_);

    if ((scanline_ & kScanLineMask) == kScanLineNone && (scanrep_ & kKeyen)) {
        if (!Model().keyen_scanline_interlock)
            HaltUnsupportedAccess("KIU KEYEN set while SCANLINE = 11 on a chip documenting no "
                                  "interlock", kBase + kOffScanRep, scanrep_);
        scanrep_ &= static_cast<uint16_t>(~kKeyen);
    }

    if (!EnabledLocked()) {
        if (sstat_ == kSStatScanning) {
            if (!Model().keyen_stop_deferred)
                HaltUnsupportedAccess("KIU KEYEN cleared during a scan on a chip documenting no "
                                      "deferral", kBase + kOffScanRep, scanrep_);
            stop_after_scan_ = true;
        } else {
            sstat_ = kSStatStopped;
        }
        return;
    }
    /* No page of the three manuals gives the precedence when SCANSTP and SCANSTART are set in
       one KIUSCANREP value (VR4111 UM 22.2.2 p463 with Fig 22-3 p473 Notes 3/4/5, VR4102 UM
       21.2.2 p426, VR4121 UM 22.2.2 p514 with Fig 22-5 p525). */
    if ((scanrep_ & kScanStp) && (scanrep_ & kScanStart))
        HaltUnsupportedAccess("KIU SCANSTP and SCANSTART set together", kBase + kOffScanRep,
                              scanrep_);

    stop_after_scan_ = false;
    ReevaluateWaitKeyInLocked();
    if ((scanrep_ & kScanStp) && sstat_ == kSStatInterval) {
        ClearScanStpLocked();
        return;
    }
    /* SCANSTART D2 - "the key scan operation starts immediately" (VR4111 UM 22.2.2 p463,
       VR4121 UM 22.2.2 p514), "starts regardless of key contact detection" (VR4102 UM 21.2.2
       p426). */
    if (!(scanrep_ & kScanStart)) return;
    /* Neither figure draws an arc leaving <scanning> for <scanning>, so no page states whether
       a scan already in progress restarts (VR4111 UM 22.2.2 p463 with Fig 22-3 p473, VR4121 UM
       22.2.2 p514 with Fig 22-5 p525, VR4102 UM 21.2.2 p425 and p426). */
    if (state_at_write == kSStatScanning)
        HaltUnsupportedAccess("KIU SCANSTART during a scan", kBase + kOffScanRep, scanrep_);
    if (sstat_ != kSStatScanning) BeginScanLocked();
}

void Vr41xxKiu::PublishCausesLocked() { emu_.Get<Vr41xxIcu>().SetKiuSource(causes_); }

uint16_t Vr41xxKiu::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - kBase;
    std::lock_guard<std::mutex> lk(mtx_);
    if (off <= kOffDat5 && (off & 1u) == 0u) {
        data_unread_ = false;
        return matrix_[off >> 1];
    }
    switch (off) {
        case kOffScanRep:  return scanrep_;
        case kOffScans:    return sstat_;
        case kOffWks:      return wks_;
        case kOffWki:      return wintvl_;
        case kOffInt:      return causes_;
        case kOffScanLine: return scanline_;
        default:           HaltUnsupportedAccess("KIU ReadHalf", addr, 0);
    }
}

void Vr41xxKiu::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - kBase;
    std::lock_guard<std::mutex> lk(mtx_);
    switch (off) {
        case kOffScanRep:
            scanrep_ = value & kScanRepMask;
            ApplyScanRepLocked();
            PublishCausesLocked();
            NotifyWorker();
            return;
        /* KIUINT D2:0 are each "Cleared to 0 when 1 is written" (VR4111 UM 22.2.6 p468,
           VR4102 UM 21.2.6 p431, VR4121 UM 22.2.6 p520). */
        case kOffInt:
            causes_ &= static_cast<uint16_t>(~(value & kIntMask));
            PublishCausesLocked();
            return;
        /* KIURST D0 "KIU reset. Cleared to 0 when 1 is written. 1: Reset"; D15:1 reserved,
           "Write 0 to these bits.  0 is returned after a read." (VR4111 UM 22.2.7 p469,
           VR4121 UM 22.2.7 p521; VR4102 UM 21.2.7 p432 words it "Write 0 when writing"). */
        case kOffRst:
            if (value & kKiuRst) ApplyResetLocked();
            NotifyWorker();
            return;
        case kOffWki:
            wintvl_ = value & kWintvlBits;
            NotifyWorker();
            return;
        /* KIUWKS T3CNT D14:10, T2CNT D9:5, T1CNT D4:0, each "((field) + 1) x 30 us" with
           "00000 : RFU" (VR4111 UM 22.2.4 p466, VR4102 UM 21.2.4 p429, VR4121 UM 22.2.4
           p518). */
        case kOffWks: {
            const uint16_t w = static_cast<uint16_t>(value & kWksMask);
            if ((w & kCntBits) == 0 || ((w >> kT2CntShift) & kCntBits) == 0 ||
                ((w >> kT3CntShift) & kCntBits) == 0)
                HaltUnsupportedAccess("KIU KIUWKS with an RFU 00000 count", addr, value);
            wks_ = w;
            return;
        }
        /* VR4111 UM Figure 22-3 p473 Note 2 with 22.2.2 p463 and VR4121 UM Figure 22-5 p525
           Note 2 with 22.2.2 p514 constrain SETTING KEYEN while the scan-line count is 0;
           VR4102 UM 21.2.2 p425 states no such interlock. None of the three says what taking
           the count to 0 under a sequencer already out of stopped does. */
        case kOffScanLine:
            if ((value & kScanLineMask) == kScanLineNone && sstat_ != kSStatStopped)
                HaltUnsupportedAccess("KIU SCANLINE = 11 while the sequencer is not stopped",
                                      addr, value);
            scanline_ = value & kScanLineMask;
            ReevaluateWaitKeyInLocked();
            PublishCausesLocked();
            NotifyWorker();
            return;
        /* KIUGPEN routes KSCAN[n] to GPIO[32+n], output value from the GIU's GIUPODATL
           (VR4111 UM 22.2.8 p470, VR4102 UM 21.2.8 p433; VR4121 UM 22.2.8 p523 names that
           register GIUPIODL). */
        case kOffGpen:     return;
        default:           HaltUnsupportedAccess("KIU WriteHalf", addr, value);
    }
}

void Vr41xxKiu::SetKeyState(uint8_t matrix_index, bool pressed) {
    if (matrix_index >= 96u)
        HaltUnsupportedAccess("KIU SetKeyState index", matrix_index, pressed);

    auto frozen = emu_.Get<EmulationFreeze>().WorkerSection();
    std::lock_guard<std::mutex> lk(mtx_);

    const uint32_t reg  = matrix_index >> 4;
    const uint16_t mask = static_cast<uint16_t>(1u << (matrix_index & 15u));
    if (((held_[reg] & mask) != 0) == pressed)
        return;

    if (pressed) held_[reg] |= mask;
    else         held_[reg] &= static_cast<uint16_t>(~mask);

    ReevaluateWaitKeyInLocked();
    PublishCausesLocked();
    NotifyWorker();
}

void Vr41xxKiu::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (uint16_t v : matrix_) w.Write("matrix", v);
    w.Write("scanrep", scanrep_);
    w.Write("causes", causes_);
    w.Write("sstat", sstat_);
    w.Write("wintvl", wintvl_);
    w.Write("wks", wks_);
    w.Write("scanline", scanline_);
    w.Write("zero_scans", zero_scans_);
    w.Write<uint8_t>("data_unread", data_unread_ ? 1u : 0u);
    w.Write<uint8_t>("stop_after_scan", stop_after_scan_ ? 1u : 0u);
    w.Write<uint8_t>("scanstart_set_while_running", scanstart_set_while_running_ ? 1u : 0u);
    w.Write<uint8_t>("scanstp_set_in_waitkeyin", scanstp_set_in_waitkeyin_ ? 1u : 0u);
}

void Vr41xxKiu::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (uint16_t& v : matrix_) r.Read("matrix", v);
    r.Read("scanrep", scanrep_);
    r.Read("causes", causes_);
    r.Read("sstat", sstat_);
    r.Read("wintvl", wintvl_);
    r.Read("wks", wks_);
    r.Read("scanline", scanline_);
    r.Read("zero_scans", zero_scans_);
    uint8_t unread = 0, stopping = 0, scanstart_held = 0, scanstp_held = 0;
    r.Read("data_unread", unread);
    r.Read("stop_after_scan", stopping);
    r.Read("scanstart_set_while_running", scanstart_held);
    r.Read("scanstp_set_in_waitkeyin", scanstp_held);
    data_unread_     = unread != 0;
    stop_after_scan_ = stopping != 0;
    scanstart_set_while_running_ = scanstart_held != 0;
    scanstp_set_in_waitkeyin_ = scanstp_held != 0;
    scan_in_flight_  = false;
    for (uint16_t& w : held_) w = 0;
}

void Vr41xxKiu::PostRestore() {
    std::lock_guard<std::mutex> lk(mtx_);
    PublishCausesLocked();
    NotifyWorker();
}

void Vr41xxKiu::NotifyWorker() {
    std::lock_guard<std::mutex> g(cv_mtx_);
    wake_seq_.fetch_add(1, std::memory_order_release);
    cv_.notify_all();
}

void Vr41xxKiu::StopWorker() {
    stop_.store(true, std::memory_order_release);
    NotifyWorker();
    if (worker_.joinable()) worker_.join();
}

/* KDATLOST when the data was not read "between when data is input to the data register after a
   key scan and when the next scan operation starts" (VR4111 UM 22.2.6 p468 D[2] cell, VR4121 UM
   22.2.6 p520 prose; VR4102 UM 21.2.6 p431 carries the bit with no such prose). */
void Vr41xxKiu::ArmScanLocked(std::chrono::steady_clock::time_point now) {
    if (data_unread_) causes_ |= kKDatLost;
    PublishCausesLocked();
    scan_in_flight_ = true;
    sstat_ = kSStatScanning;
    phase_end_ = now + std::chrono::microseconds(ScanPeriodUsLocked());
}

/* A scan set occupies one scan period, and "the interval after the completion of the scan of a
   set of key data until the start of the next scan is set on the KIUWKIREG" (VR4102 UM 21.2.3
   p428; VR4111 UM 22.2.4 p466 / 22.2.5 p467, VR4121 UM 22.2.4 p518 / 22.2.5 p519; the two arcs
   are VR4111 UM Fig 22-3 p473 and VR4121 UM Fig 22-5 p525). */
void Vr41xxKiu::AdvancePhaseLocked() {
    const auto now = std::chrono::steady_clock::now();
    if (sstat_ == kSStatScanning && !scan_in_flight_) {
        ArmScanLocked(now);
        return;
    }
    if (now < phase_end_) return;
    if (sstat_ == kSStatScanning) {
        scan_in_flight_ = false;
        CompleteScanLocked();
        PublishCausesLocked();
        if (sstat_ == kSStatInterval)
            phase_end_ = now + std::chrono::microseconds(
                                   static_cast<uint32_t>(wintvl_) * kTimeUnitUs);
        return;
    }
    if (sstat_ == kSStatInterval) ArmScanLocked(now);
}

void Vr41xxKiu::WorkerLoop() {
    auto& freeze = emu_.Get<EmulationFreeze>();
    std::unique_lock<std::mutex> lk(cv_mtx_);
    while (!stop_.load(std::memory_order_acquire)) {
        const uint64_t seq = wake_seq_.load(std::memory_order_acquire);
        lk.unlock();
        bool timed = false;
        std::chrono::steady_clock::time_point until;
        {
            auto frozen = freeze.WorkerSection();
            std::lock_guard<std::mutex> sl(mtx_);
            AdvancePhaseLocked();
            timed = sstat_ == kSStatScanning || sstat_ == kSStatInterval;
            until = phase_end_;
        }
        lk.lock();
        const auto woken = [this, seq] {
            return stop_.load(std::memory_order_acquire) ||
                   wake_seq_.load(std::memory_order_acquire) != seq;
        };
        if (timed) cv_.wait_until(lk, until, woken);
        else       cv_.wait(lk, woken);
    }
}
