#pragma once

#include "vr41xx_piu.h"

#include "vr41xx_piu_panel.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "vr41xx_icu.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <optional>
#include <thread>

#include "vr41xx_piu_regs.h"

namespace cerf_vr41xx_piu_detail {


template <SocFamily Soc, Vr41xxPiuModel M>
class Vr41xxPiuBase : public Vr41xxPiu {
public:
    using Vr41xxPiu::Vr41xxPiu;

    ~Vr41xxPiuBase() override { StopWorker(); }
    void OnShutdown() override { StopWorker(); }

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == Soc;
    }

    /* Every PIU register's RTCRST column equals its other-resets column (VR4121 UM
       20.3.1-20.3.10, VR4102 UM 19.3.1-19.3.10). */
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        worker_ = std::thread([this] { WorkerLoop(); });
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            std::lock_guard<std::mutex> lk(mtx_);
            ApplyResetLocked();
        });
    }

    uint32_t MmioBase() const override { return M.base; }
    uint32_t MmioSize() const override { return M.size; }
    uint32_t Piu2Base() const override { return M.piu2_base; }
    uint32_t Piu2Size() const override { return M.piu2_size; }

    uint16_t ReadHalf(uint32_t addr) override {
        std::lock_guard<std::mutex> lk(mtx_);
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
            case kOffAscn: ascn_ = value & 0x0003u; return;
            case kOffAmsk: amsk_ = value & 0x00FFu; return;
            default: HaltUnsupportedAccess("VR41xx PIU WriteHalf", addr, value);
        }
    }

    uint8_t  ReadByte (uint32_t addr) override { HaltUnsupportedAccess("VR41xx PIU ReadByte", addr, 0); }
    uint32_t ReadWord (uint32_t addr) override { HaltUnsupportedAccess("VR41xx PIU ReadWord", addr, 0); }
    void WriteByte(uint32_t addr, uint8_t  v) override { HaltUnsupportedAccess("VR41xx PIU WriteByte", addr, v); }
    void WriteWord(uint32_t addr, uint32_t v) override { HaltUnsupportedAccess("VR41xx PIU WriteWord", addr, v); }

    /* PIUABnREG holds ADPortScan data in AB0-3 and CMDScanDATA in AB0 (VR4121 UM Table 20-5,
       VR4102 UM Table 19-5). */
    uint16_t ReadHalf2(uint32_t off) override {
        std::lock_guard<std::mutex> lk(mtx_);
        if (off == kOffAb0 || off == kOffAb1 || off == kOffAb2 || off == kOffAb3)
            return adbuf_[(off - kOffAb0) / 2u];
        int page = 0, idx = 0;
        if (BufferSlot(off, &page, &idx)) return page_buf_[page][idx];
        HaltUnsupportedAccess("VR41xx PIU2 ReadHalf", M.piu2_base + off, 0);
    }

    /* PIUPBnmREG D15 VALID + D9:0 PADDATA are R/W, D14:10 RFU "write 0 / read 0" (VR4121 UM
       20.3.9, VR4102 UM 19.3.9); touch.dll sub_1370AB0 masks each page buffer to 10 bits and
       writes it back while recovering the coordinate. */
    void WriteHalf2(uint32_t off, uint16_t value) override {
        std::lock_guard<std::mutex> lk(mtx_);
        int page = 0, idx = 0;
        if (BufferSlot(off, &page, &idx)) {
            page_buf_[page][idx] = value & 0x83FFu;
            return;
        }
        HaltUnsupportedAccess("VR41xx PIU2 WriteHalf", M.piu2_base + off, value);
    }

    void SetPen(bool down, uint16_t pos_x, uint16_t pos_y) override {
        {
            auto frozen = emu_.Get<EmulationFreeze>().WorkerSection();
            std::lock_guard<std::mutex> lk(mtx_);
            pos_x_ = pos_x & 0x3FFu;
            pos_y_ = pos_y & 0x3FFu;
            synthetic_hold_ = 0;
            if (down != pen_cur_) PenEdgeLocked(down);
        }
        wake_.store(true, std::memory_order_release);
        cv_.notify_all();
    }

    void SyntheticTap(uint16_t pos_x, uint16_t pos_y) override {
        {
            auto frozen = emu_.Get<EmulationFreeze>().WorkerSection();
            std::lock_guard<std::mutex> lk(mtx_);
            if (pen_cur_) return;
            pos_x_ = pos_x & 0x3FFu;
            pos_y_ = pos_y & 0x3FFu;
            synthetic_hold_ = kSyntheticHoldScans;
            PenEdgeLocked(true);
        }
        wake_.store(true, std::memory_order_release);
        cv_.notify_all();
    }

    void SaveState(StateWriter& w) override {
        std::lock_guard<std::mutex> lk(mtx_);
        w.Write(state_); w.Write(cnt_cfg_); w.Write(intreg_);
        w.Write(sivl_); w.Write(stbl_); w.Write(cmd_);
        w.Write<uint8_t>(pen_prev_ ? 1 : 0);
        w.Write<uint8_t>(penstc_ ? 1 : 0);
        w.Write(pos_x_); w.Write(pos_y_);
        for (auto& pg : page_buf_) for (uint16_t b : pg) w.Write(b);
        w.Write(next_page_);
        for (uint16_t b : adbuf_) w.Write(b);
        w.Write(ascn_);
        w.Write(amsk_);
    }

    void RestoreState(StateReader& r) override {
        std::lock_guard<std::mutex> lk(mtx_);
        r.Read(state_); r.Read(cnt_cfg_); r.Read(intreg_);
        r.Read(sivl_); r.Read(stbl_); r.Read(cmd_);
        uint8_t prev = 0, stc = 0;
        r.Read(prev); r.Read(stc);
        r.Read(pos_x_); r.Read(pos_y_);
        for (auto& pg : page_buf_) for (uint16_t& b : pg) r.Read(b);
        r.Read(next_page_);
        for (uint16_t& b : adbuf_) r.Read(b);
        r.Read(ascn_);
        r.Read(amsk_);
        /* PIUCNTREG D14 PENSTP "Previous touch panel contact state" (R/W) and D13 PENSTC
           "Current touch panel contact state" (VR4102 UM 19.3.1); "when PENCHGINTR is
           cleared to 0, PENSTC indicates the touch panel contact state" (VR4121 UM 20.3.2). */
        pen_cur_  = false;
        pen_prev_ = (prev != 0);
        penstc_   = (stc != 0);
        LatchPenstcLocked();
        if (state_ == kStPenDataScan || state_ == kStIntervalNext) state_ = kStWaitPenTouch;
    }

    void PostRestore() override {
        std::lock_guard<std::mutex> lk(mtx_);
        DriveIcuLocked();
    }

private:
    uint16_t PiuMode() const { return (cnt_cfg_ >> 3) & 0x3u; }

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
            if (state_ == kStPenDataScan) SampleOnceLocked();
        } else if (state_ == kStPenDataScan && (cnt_cfg_ & kAtStop)) {
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
        if (clr & kPage0Intr) for (uint16_t& b : page_buf_[0]) b &= ~kValid;
        if (clr & kPage1Intr) for (uint16_t& b : page_buf_[1]) b &= ~kValid;
        if (clr & kPadAdpIntr) for (uint16_t& b : adbuf_) b &= ~kValid;
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

        /* PIUPWR "1: Set PIU output as active and change to standby mode / 0: Set panel to
           touch detection state and shift to PIU operation stop enabled mode"; PIUSEQEN
           "scan sequencer operation enable"; PIUMODE "00: Sample coordinate data / 01:
           Operate A/D converter using any command" (VR4121 UM 20.3.1, VR4102 UM 19.3.1). */
        const bool pwr0 = (old & kPiuPwr) != 0, pwr1 = (cnt_cfg_ & kPiuPwr) != 0;
        if (!pwr0 && pwr1 && state_ == kStDisable) state_ = kStStandby;
        else if (pwr0 && !pwr1)                    state_ = kStDisable;

        const bool seq0 = (old & kSeqEn) != 0, seq1 = (cnt_cfg_ & kSeqEn) != 0;
        if (!seq0 && seq1 && state_ == kStStandby) {
            /* Standby -> ADPortScan on "PIUSeqEN = 1 & ADPSStart = 1"; the scan completes and
               the state returns to the pre-scan Standby (VR4121 UM Figure 20-4 + 20.2 (3),
               VR4102 UM Figure 19-4 + 19.2). */
            if (ascn_ & kAdpsStart) {
                AdPortScanOnceLocked();
                DriveIcuLocked();
            } else {
                state_ = (PiuMode() == 1) ? kStCmdScan : kStWaitPenTouch;
            }
        } else if (seq0 && !seq1 && state_ != kStDisable) {
            state_ = kStStandby;
        }

        /* touch.dll sub_15A04A8 flips PIUMODE from command back to coordinate with
           PIUSEQEN still set. */
        if (((old >> 3) & 0x3u) != PiuMode() && seq1 &&
            state_ != kStDisable && state_ != kStStandby) {
            state_ = (PiuMode() == 1) ? kStCmdScan : kStWaitPenTouch;
        }

        /* PADATSTART "1: Auto start during touch state" (VR4121 UM 20.3.1, VR4102 UM
           19.3.1). */
        if (pen_cur_ && (cnt_cfg_ & kSeqEn) && (cnt_cfg_ & kAtStart) &&
            state_ == kStWaitPenTouch) {
            state_ = kStPenDataScan;
            SampleOnceLocked();
            DriveIcuLocked();
            wake_.store(true, std::memory_order_release);
            cv_.notify_all();
        } else if (pen_cur_ && state_ == kStCmdScan) {
            /* A command scan fetches "one port only" per PIUSEQEN kick and CmdScan has no
               self-loop (VR4121 UM 20.2 (4), Figure 20-4; VR4102 UM 19.2, Figure 19-4);
               touch.dll sub_15A0E24 re-arms "PIUCNTREG |= PIUSEQEN" after every sample. */
            CmdScanOnceLocked();
            DriveIcuLocked();
            wake_.store(true, std::memory_order_release);
            cv_.notify_all();
        }
    }

    /* Page-buffer slots, from PIUPB00REG at piu2_base (VR4121 UM Table 20-1 == VR4102 UM
       Table 19-1): PIUPBn0-3 at +0x00/02/04/06 (page 0) and +0x08/0A/0C/0E (page 1),
       PIUPB04REG at +0x1C and PIUPB14REG at +0x1E. */
    static bool BufferSlot(uint32_t off, int* page, int* idx) {
        switch (off) {
            case 0x00: *page = 0; *idx = 0; return true;
            case 0x02: *page = 0; *idx = 1; return true;
            case 0x04: *page = 0; *idx = 2; return true;
            case 0x06: *page = 0; *idx = 3; return true;
            case 0x1C: *page = 0; *idx = 4; return true;
            case 0x08: *page = 1; *idx = 0; return true;
            case 0x0A: *page = 1; *idx = 1; return true;
            case 0x0C: *page = 1; *idx = 2; return true;
            case 0x0E: *page = 1; *idx = 3; return true;
            case 0x1E: *page = 1; *idx = 4; return true;
            default:   return false;
        }
    }

    void SampleOnceLocked() {
        /* VR4111 UM Table 20-4 and VR4121 UM Table 20-4 name PIUPBn0 X- and PIUPBn1 X+, VR4102
           UM Table 19-4 the reverse, yet every driver recovers (PIUPBn0 - PIUPBn1 + 1023) >> 1:
           nec_mobilepro_700_ce2 touch.dll sub_15A0BB0, casio_toricomail_ce212 touch.dll
           sub_1370AB0, casio_cassiopeia_e55 touch.dll sub_14D073C. Slot 0 rises. */
        const int page = next_page_;
        uint16_t (&buf)[5] = page_buf_[page];
        const uint16_t x_rise = static_cast<uint16_t>(pos_x_ & 0x3FFu);
        const uint16_t x_fall = static_cast<uint16_t>((kAdcMax - pos_x_) & 0x3FFu);
        const uint16_t y_rise = static_cast<uint16_t>(pos_y_ & 0x3FFu);
        const uint16_t y_fall = static_cast<uint16_t>((kAdcMax - pos_y_) & 0x3FFu);
        buf[0] = kValid | x_rise;
        buf[1] = kValid | x_fall;
        buf[2] = kValid | y_rise;
        buf[3] = kValid | y_fall;
        const std::optional<uint16_t> z = emu_.Get<Vr41xxPiuPanel>().PressureSample();
        buf[4] = z ? static_cast<uint16_t>(kValid | (*z & 0x3FFu)) : 0u;

        /* PIUINTREG OVP "1: Valid data older than page 1 buffer data is retained / 0: Valid
           data older than page 0 buffer data is retained" (VR4121 UM 20.3.2, VR4102 UM
           19.3.2). */
        intreg_ |= (page == 0) ? kPage0Intr : kPage1Intr;
        intreg_ = (intreg_ & ~kOvp) | ((page == 1) ? kOvp : 0u);
        next_page_ ^= 1;
    }

    /* PIUAB0REG's D15 VALID is "1: Valid / 0: Invalid" (VR4121 UM 20.3.10, VR4102 UM
       19.3.10). PIUINTREG D6 PADCMDINTR is "1: Indicates that command scan found valid data
       / 0: Indicates that command scan did not find valid data in buffer" (VR4121 UM 20.3.2,
       VR4102 UM 19.3.2). */
    void CmdScanOnceLocked() {
        const std::optional<uint16_t> val =
            emu_.Get<Vr41xxPiuPanel>().ConvertCommandPort(
                static_cast<uint16_t>(cmd_ & 0x000Fu), pos_x_, pos_y_);
        adbuf_[0] = val ? static_cast<uint16_t>(kValid | (*val & 0x3FFu)) : 0u;
        if (val) intreg_ |= kPadCmdIntr;
    }

    /* Buffer slot n's port = (TPPSCAN?0:4)+n; PIUAMSKREG bit index = that port (VR4121 UM
       Table 20-5 + 20.3.7, VR4102 UM Table 19-5 + 19.3.7). The scan raises PADADPINTR (D5) -
       NOT PADCMDINTR (D6), which chapter 20.2(3)/19.2(3) wrongly names (VR4121 UM 20.3.2,
       VR4102 UM 19.3.2). */
    void AdPortScanOnceLocked() {
        const uint16_t port_base = (ascn_ & kTppScan) ? 0u : 4u;
        bool any_valid = false;
        for (uint16_t slot = 0; slot < 4u; ++slot) {
            const uint16_t port = port_base + slot;
            if (amsk_ & (1u << port)) { adbuf_[slot] = 0; continue; }
            const std::optional<uint16_t> v =
                emu_.Get<Vr41xxPiuPanel>().AdPortScanSample(port);
            if (v) { adbuf_[slot] = static_cast<uint16_t>(kValid | (*v & 0x3FFu)); any_valid = true; }
            else   { adbuf_[slot] = 0; }
        }
        if (any_valid) intreg_ |= kPadAdpIntr;
        ascn_ &= ~kAdpsStart;
    }

    /* The ICU's PIUINTREG (0x0B000082) carries the PIU's interrupt causes and raises
       SYSINT1REG PIUINTR when unmasked (VR4121 UM 15.1, VR4102 UM 14.1). */
    void DriveIcuLocked() {
        emu_.Get<Vr41xxIcu>().SetPiuSource(intreg_ & kIntCauses);
    }

    /* "Interval = SCANINTVAL(10:0) x 30 us" (VR4121 UM 20.3.3, VR4102 UM 19.3.3). */
    uint32_t IntervalMsLocked() const {
        const uint32_t us = static_cast<uint32_t>(sivl_ & 0x07FFu) * 30u;
        return std::clamp<uint32_t>(us / 1000u, 5u, 100u);
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
        for (auto& pg : page_buf_) for (uint16_t& b : pg) b = 0;
        next_page_ = 0;
        for (uint16_t& b : adbuf_) b = 0;
        ascn_      = 0;
        amsk_      = 0;
        DriveIcuLocked();
    }

    void StopWorker() {
        stop_.store(true, std::memory_order_release);
        cv_.notify_all();
        if (worker_.joinable()) worker_.join();
    }

    void WorkerLoop() {
        auto& freeze = emu_.Get<EmulationFreeze>();
        std::unique_lock<std::mutex> lk(cv_mtx_);
        while (!stop_.load(std::memory_order_acquire)) {
            lk.unlock();
            bool sampled = false;
            uint32_t interval = 20;
            {
                auto frozen = freeze.WorkerSection();
                std::lock_guard<std::mutex> sl(mtx_);
                if (pen_cur_ && state_ == kStPenDataScan) {
                    SampleOnceLocked();
                    DriveIcuLocked();
                    interval = IntervalMsLocked();
                    sampled = true;
                    if (synthetic_hold_ != 0 && --synthetic_hold_ == 0) PenEdgeLocked(false);
                } else if (pen_cur_ && state_ == kStCmdScan) {
                    CmdScanOnceLocked();
                    DriveIcuLocked();
                    interval = IntervalMsLocked();
                    sampled = true;
                }
            }
            lk.lock();
            if (stop_.load(std::memory_order_acquire)) break;
            if (sampled) {
                cv_.wait_for(lk, std::chrono::milliseconds(interval));
            } else {
                cv_.wait(lk, [this] {
                    return stop_.load(std::memory_order_acquire) ||
                           wake_.exchange(false, std::memory_order_acq_rel);
                });
            }
        }
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

    uint16_t page_buf_[2][5] = {};
    uint16_t next_page_      = 0;
    uint16_t adbuf_[4]       = {};   /* PIUAB0-3REG */
    uint16_t ascn_           = 0;    /* PIUASCNREG */
    uint16_t amsk_           = 0;    /* PIUAMSKREG */

    std::mutex              cv_mtx_;
    std::condition_variable cv_;
    std::thread             worker_;
    std::atomic<bool>       stop_{false};
    std::atomic<bool>       wake_{false};
};

}  /* namespace cerf_vr41xx_piu_detail */
