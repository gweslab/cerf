#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../host/host_gdiplus.h"
#include "../../host/host_widget.h"
#include "../../host/host_widget_registry.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "vr41xx_icu.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

namespace cerf_vr41xx_led_detail {

/* VR4111 UM Table 24-1 p493 and VR4102 UM 23.2.1-23.2.5 p454-p458 give 0x0B000240/0242/0248/
   024A/024C; VR4131 UM 19.2.1-19.2.5 p359-p363 give 0x0F000180/0182/0188/018A/018C. */
constexpr uint32_t kOffHts   = 0x00u;
constexpr uint32_t kOffLts   = 0x02u;
constexpr uint32_t kOffHltcl = 0x04u;
constexpr uint32_t kOffHltch = 0x06u;
constexpr uint32_t kOffCnt   = 0x08u;
constexpr uint32_t kOffAstc  = 0x0Au;
constexpr uint32_t kOffInt   = 0x0Cu;

/* LEDHLTCLREG and LEDHLTCHREG, initial value 0x0000, listed between LEDLTSREG and LEDCNTREG in
   the operation flow's "Register initial setting" (VR4111 UM 24.3 p499 / VR4131 UM 19.3 p364).
   The VR4102 manual names neither, but nec_mobilepro_700_ce2 leddrv.dll sub_153054C writes both
   on that chip: @0x15305AC "sh $zero, 0x244($t7)" and @0x15305B8 "sh $zero, 0x246($t8)". */
constexpr uint16_t kHltcPowerOn = 0x0000u;

/* HTS[4..0] is "Values compared to bits 15 to 11 of LED HL Time Count" (VR4111 UM 24.2.1 p494)
   and LTS[6..0] "Values compared to bits 17 to 11" (24.2.2 p495), both scaling bit 11 as
   0.0625 seconds. */
constexpr uint32_t kHltcHz        = 32768u;
constexpr uint32_t kHltcUnitShift = 11u;

/* LEDCNTREG D1 LEDSTOP enables blink auto-stop and D0 LEDENABLE starts blinking; at auto-stop
   counter zero the unit clears both and sets LEDINT (VR4111 UM 24.3 p499). */
constexpr uint16_t kCntStop = 0x0002u;

/* LEDINT "Generates an interrupt request for the ICU unit" (VR4111 UM 24.3 p499); LEDINTR is
   D[1] of SYSINT2REG 0x0B000200 (VR4111 UM 15.2.15 p345). */
constexpr uint16_t kIcuLedintBit = 0x0002u;

/* LEDCNTREG: D1 LEDSTOP | D0 LEDENABLE R/W, D15:2 reserved read-0; RTCRST = LEDSTOP(1)/
   LEDENABLE(0), other resets retain (VR4111 UM 24.2.3 p496 / VR4102 UM 23.2.3 p456 /
   VR4131 UM 19.2.3 p361). */
constexpr uint16_t kCntMask    = 0x0003u;
constexpr uint16_t kCntEnable  = 0x0001u;
constexpr uint16_t kCntPowerOn = 0x0002u;

/* LEDHTSREG on-time D[4:0], LEDLTSREG off-time D[6:0], both in 0.0625 s units,
   RTCRST 1 s and 2 s respectively (VR4111 UM 24.2.1 p494 + 24.2.2 p495 /
   VR4102 UM 23.2.1 p454 + 23.2.2 p455 / VR4131 UM 19.2.1 p359 + 19.2.2 p360). */
constexpr uint16_t kHtsWritable = 0x001Fu;
constexpr uint16_t kLtsWritable = 0x007Fu;
constexpr uint16_t kHtsPowerOn  = 0x0010u;
constexpr uint16_t kLtsPowerOn  = 0x0020u;

/* LEDASTCREG D[15:0] R/W, RTCRST and other resets 1,200 (VR4111 UM 24.2.4 p497 /
   VR4102 UM 23.2.4 p457 / VR4131 UM 19.2.4 p362). */
constexpr uint16_t kAstcPowerOn = 0x04B0u;

/* LEDINTREG D0 LEDINT R/W "Cleared to 0 when 1 is written",
   D15:1 reserved read-0, both reset rows 0 (VR4111 UM 24.2.5 p498 / VR4102 UM 23.2.5 p458 /
   VR4131 UM 19.2.5 p363). */
constexpr uint16_t kIntLedint = 0x0001u;

const COLORREF kClrLit      = RGB(78, 201, 90);
const COLORREF kClrDark     = RGB(50, 55, 50);
const COLORREF kClrRim      = RGB(90, 95, 90);
const COLORREF kClrRimBlink = RGB(120, 230, 130);

template <SocFamily Soc, uint32_t Base>
class Vr41xxLedBase : public Peripheral, public HostWidget {
public:
    using Peripheral::Peripheral;

    ~Vr41xxLedBase() override { StopWorker(); }
    void OnShutdown() override { StopWorker(); }

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == Soc;
    }
    void OnReady() override {
        hltc_anchor_ = Clock::now();
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<HostWidgetRegistry>().Register(this);
        /* LEDASTCREG and LEDINTREG carry identical RTCRST and Other-resets rows, while
           LEDHTSREG, LEDLTSREG and LEDCNTREG carry "Previous value is retained" on Other
           resets (VR4111 UM 24.2.1-24.2.5 p494-p498 / VR4102 UM 23.2.1-23.2.5 p454-p458 /
           VR4131 UM 19.2.1-19.2.5 p359-p363). */
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind kind) {
            std::lock_guard<std::mutex> lk(state_mutex_);
            astc_ = kAstcPowerOn;
            int_  = 0;
            if (kind == ResetLineKind::Rtc) {
                cnt_ = kCntPowerOn;
                hts_ = kHtsPowerOn;
                lts_ = kLtsPowerOn;
                ReanchorHltcLocked(kHltcPowerOn);
            }
            if (cnt_ & kCntEnable) ArmBlinkLocked();
            else                   astc_remaining_ = 0;
            DriveIcuLocked();
        });
        worker_ = std::thread([this] { WorkerLoop(); });
    }

    uint32_t MmioBase() const override { return Base; }
    /* The unit decodes a 0x20 window: "0x0B00 025F to 0x0B00 0240 LED" (VR4111 UM Table 6-10
       p170) and "0x0F00 019F to 0x0F00 0180 LED" (VR4131 UM Table 3-6 p82). */
    uint32_t MmioSize() const override { return 0x20u; }

    uint16_t ReadHalf(uint32_t addr) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        switch (addr - Base) {
            case kOffHts: return hts_;
            case kOffLts: return lts_;
            case kOffHltcl: return static_cast<uint16_t>(HltcNowLocked());
            case kOffHltch: return static_cast<uint16_t>(HltcNowLocked() >> 16);
            case kOffCnt: return cnt_;
            /* LEDASTCREG "The set value is read during a read" (VR4111 UM 24.2.4 p497). */
            case kOffAstc: return astc_;
            /* casio_cassiopeia_em500_ppc2000 gwes.exe sub_74CBC @0x74D0E "jalx sub_1C138",
               whose body is "*a1 = a2; return *a3;" with a3 = LEDINTREG. */
            case kOffInt: return int_;
            default: HaltUnsupportedAccess("LED ReadHalf", addr, 0);
        }
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            switch (addr - Base) {
                case kOffHts:
                    hts_ = static_cast<uint16_t>(value & kHtsWritable);
                    NoteTimeChangeLocked("LEDHTSREG", value);
                    return;
                case kOffLts:
                    lts_ = static_cast<uint16_t>(value & kLtsWritable);
                    NoteTimeChangeLocked("LEDLTSREG", value);
                    return;
                case kOffHltcl:
                    ReanchorHltcLocked((HltcNowLocked() & 0xFFFF0000u) | value);
                    return;
                case kOffHltch:
                    ReanchorHltcLocked((HltcNowLocked() & 0x0000FFFFu) |
                                       (static_cast<uint32_t>(value) << 16));
                    return;
                case kOffCnt:
                    WriteCntLocked(static_cast<uint16_t>(value & kCntMask));
                    break;
                case kOffAstc: WriteAstcLocked(value); return;
                case kOffInt:
                    int_ = static_cast<uint16_t>(int_ & ~(value & kIntLedint));
                    DriveIcuLocked();
                    return;
                default: HaltUnsupportedAccess("LED WriteHalf", addr, value);
            }
        }
        NotifyWorker();
    }
    void WriteByte(uint32_t addr, uint8_t value) override {
        HaltUnsupportedAccess("LED WriteByte", addr, value);
    }
    /* casio_cassiopeia_e55 gwes.exe sub_AC1EC @0xAC244 "sw $t6, 0x240($t7)" and @0xAC250
       "sw $zero, 0x244($t8)"; nec_mobilepro_700_ce2 leddrv.dll sub_153054C @0x15305D8
       "sw $t3, 0x240($t4)". */
    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - Base;
        if (off != kOffHts && off != kOffHltcl)
            HaltUnsupportedAccess("LED WriteWord", addr, value);
        WriteHalf(Base + off,      static_cast<uint16_t>(value));
        WriteHalf(Base + off + 2u, static_cast<uint16_t>(value >> 16));
    }

    uint8_t  ReadByte (uint32_t addr) override { HaltUnsupportedAccess("LED ReadByte", addr, 0); }
    uint32_t ReadWord (uint32_t addr) override { HaltUnsupportedAccess("LED ReadWord", addr, 0); }

    void SaveState(StateWriter& w) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        w.Write(cnt_); w.Write(hts_); w.Write(lts_); w.Write(astc_); w.Write(int_);
        w.Write(HltcNowLocked());
        w.Write(astc_remaining_);
    }
    void RestoreState(StateReader& r) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        r.Read(cnt_); r.Read(hts_); r.Read(lts_); r.Read(astc_); r.Read(int_);
        uint32_t hltc = 0;
        r.Read(hltc); r.Read(astc_remaining_);
        ReanchorHltcLocked(hltc);
        last_pair_index_ = (cnt_ & kCntEnable) ? PairIndexLocked() : 0;
    }
    void PostRestore() override {
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            DriveIcuLocked();
        }
        NotifyWorker();
    }

    std::wstring WidgetName() const override { return L"Notification LED"; }
    WidgetGroup  Group() const override { return WidgetGroup::Indicator; }
    std::wstring Tooltip() const override {
        uint16_t cnt, hts, lts;
        { std::lock_guard<std::mutex> lk(state_mutex_); cnt = cnt_; hts = hts_; lts = lts_; }
        wchar_t buf[96];
        if (cnt & kCntEnable)
            swprintf_s(buf, L"Notification LED: blinking (on %ums / off %ums)",
                       static_cast<unsigned>(hts) * 125u / 2u,
                       static_cast<unsigned>(lts) * 125u / 2u);
        else
            swprintf_s(buf, L"Notification LED: off");
        return buf;
    }
    void DrawIcon(HDC dc, const RECT& box) const override {
        const int cx = (box.left + box.right) / 2;
        const int cy = (box.top + box.bottom) / 2;
        constexpr int kR = 5;
        emu_.Get<HostGdiPlus>().FillCircleAA(dc, cx, cy, kR,
            draw_lit_ ? kClrLit : kClrDark,
            draw_blink_ ? kClrRimBlink : kClrRim);
    }
    bool PollDirty() override {
        bool blink = false, lit = false;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            blink = (cnt_ & kCntEnable) != 0u;
            if (blink) lit = (HltcUnitsLocked() % (hts_ + lts_)) < hts_;
        }
        if (lit == draw_lit_ && blink == draw_blink_) return false;
        draw_lit_   = lit;
        draw_blink_ = blink;
        return true;
    }

private:
    using Clock = std::chrono::steady_clock;

    uint64_t ElapsedHltcTicksLocked() const {
        const auto d = Clock::now() - hltc_anchor_;
        return static_cast<uint64_t>(std::chrono::duration_cast<
            std::chrono::duration<int64_t, std::ratio<1, kHltcHz>>>(d).count());
    }
    uint32_t HltcNowLocked() const {
        return static_cast<uint32_t>(hltc_base_ + ElapsedHltcTicksLocked());
    }
    uint64_t HltcUnitsLocked() const {
        return (hltc_base_ + ElapsedHltcTicksLocked()) >> kHltcUnitShift;
    }
    void ReanchorHltcLocked(uint32_t value) {
        hltc_base_   = value;
        hltc_anchor_ = Clock::now();
        if (cnt_ & kCntEnable) last_pair_index_ = PairIndexLocked();
    }

    uint64_t PairIndexLocked() const {
        return HltcUnitsLocked() / (hts_ + lts_);
    }
    void ArmBlinkLocked() {
        last_pair_index_ = PairIndexLocked();
        astc_remaining_  = astc_;
    }

    /* "This register is a 16-bit down counter that sets the number of ON/OFF times prior to
       automatic stopping of LED activation" and "Setting a zero to this register is
       prohibited" (VR4111 UM 24.2.4 p497). */
    void WriteAstcLocked(uint16_t value) {
        astc_ = value;
        if (!(cnt_ & kCntEnable)) return;
        if (!value)
            emu_.Get<Fatal>().Die("VR41xx LED: LEDASTCREG written 0 while LEDENABLE is set");
        last_pair_index_ = PairIndexLocked();
        astc_remaining_  = value;
    }

    /* Zero in LEDHTSREG or LEDLTSREG is prohibited at the blinking start condition
       (VR4111 UM 24.3 p499; the VR4131 equivalent is 19.3 p364). */
    void NoteTimeChangeLocked(const char* reg, uint16_t value) {
        if (!(cnt_ & kCntEnable)) return;
        LOG(Periph, "[LED] %s=0x%04X written while LEDENABLE is set; blink timing undefined\n",
            reg, value);
        if (!hts_ || !lts_)
            emu_.Get<Fatal>().Die("VR41xx LED: %s=0x%04X leaves LEDHTSREG=0x%04X "
                                  "LEDLTSREG=0x%04X while LEDENABLE is set; zero is prohibited",
                                  reg, value, hts_, lts_);
        last_pair_index_ = PairIndexLocked();
    }

    /* "Setting these registers to 0 is prohibited because this operation may cause undefined
       operation", bracketing LEDHTSREG / LEDLTSREG / LEDASTCREG at the blinking start
       condition (VR4111 UM 24.3 p499); the VR4131 equivalent is 19.3 p364. */
    void WriteCntLocked(uint16_t value) {
        const bool was_enabled = (cnt_ & kCntEnable) != 0u;
        const bool now_enabled = (value & kCntEnable) != 0u;
        if (now_enabled && !was_enabled) {
            if (!hts_ || !lts_ || !astc_)
                emu_.Get<Fatal>().Die("VR41xx LED: LEDENABLE set with LEDHTSREG=0x%04X "
                                      "LEDLTSREG=0x%04X LEDASTCREG=0x%04X; zero is prohibited",
                                      hts_, lts_, astc_);
            cnt_ = value;
            ArmBlinkLocked();
            return;
        }
        cnt_ = value;
    }

    /* "The pair of operations in which the LED is switched ON once and OFF once is counted as
       '1' by this counter. The counter counts down from the set value and an LEDINT interrupt
       occurs when it reaches zero" (VR4111 UM 24.2.4 p497); at zero the flow clears LEDENABLE
       and LEDSTOP and sets LEDINT (24.3 p499 / VR4131 UM 19.3 p364). */
    void EvaluateLocked() {
        if (!(cnt_ & kCntEnable)) return;
        const uint64_t idx = PairIndexLocked();
        if (idx != last_pair_index_) {
            const uint64_t advance = idx > last_pair_index_ ? idx - last_pair_index_ : 0;
            last_pair_index_ = idx;
            if ((cnt_ & kCntStop) && advance)
                astc_remaining_ = advance >= astc_remaining_
                                      ? 0
                                      : static_cast<uint16_t>(astc_remaining_ - advance);
        }
        if (!(cnt_ & kCntStop) || astc_remaining_) return;
        cnt_ = static_cast<uint16_t>(cnt_ & ~(kCntStop | kCntEnable));
        int_ = static_cast<uint16_t>(int_ | kIntLedint);
    }
    void DriveIcuLocked() {
        emu_.Get<Vr41xxIcu>().SetSysint2Source(kIcuLedintBit, (int_ & kIntLedint) != 0);
    }

    void NotifyWorker() { std::lock_guard<std::mutex> g(cv_mtx_); cv_.notify_all(); }
    void StopWorker() {
        stop_.store(true, std::memory_order_release);
        NotifyWorker();
        if (worker_.joinable()) worker_.join();
    }
    void WorkerLoop() {
        auto& freeze = emu_.Get<EmulationFreeze>();
        std::unique_lock<std::mutex> lk(cv_mtx_);
        while (!stop_.load(std::memory_order_acquire)) {
            lk.unlock();
            {
                auto frozen = freeze.WorkerSection();
                std::lock_guard<std::mutex> sl(state_mutex_);
                EvaluateLocked();
                DriveIcuLocked();
            }
            lk.lock();
            if (stop_.load(std::memory_order_acquire)) break;
            cv_.wait_for(lk, std::chrono::milliseconds(10));
        }
    }

    mutable std::mutex state_mutex_;

    uint16_t cnt_   = kCntPowerOn;
    uint16_t hts_   = kHtsPowerOn;
    uint16_t lts_   = kLtsPowerOn;
    uint16_t astc_  = kAstcPowerOn;
    uint16_t int_   = 0;

    uint32_t          hltc_base_   = 0;
    Clock::time_point hltc_anchor_ = {};

    uint64_t last_pair_index_ = 0;
    uint16_t astc_remaining_  = 0;

    std::mutex              cv_mtx_;
    std::condition_variable cv_;
    std::thread             worker_;
    std::atomic<bool>       stop_{false};

    bool draw_lit_   = false;
    bool draw_blink_ = false;
};

}  /* namespace cerf_vr41xx_led_detail */
