#pragma once

#include "../peripherals/peripheral_base.h"

#include "../boards/board_context.h"
#include "../core/cerf_emulator.h"
#include "../core/fatal.h"
#include "../jit/guest_cycle_clock.h"
#include "../peripherals/peripheral_dispatcher.h"
#include "../state/state_stream.h"
#include "cycle_anchored_counter.h"
#include "freescale_timer_clocks.h"
#include "guest_cpu_reset.h"

#include <cstdint>
#include <string_view>

namespace cerf_freescale_wdog_detail {

constexpr uint32_t kSize = 0x00004000u;

/* MCIMX31RM Table 37-3 / MCIMX51RM Table 62-2. */
constexpr uint32_t kWcr  = 0x00u;
constexpr uint32_t kWsr  = 0x02u;
constexpr uint32_t kWrsr = 0x04u;
constexpr uint32_t kWicr = 0x06u;
constexpr uint32_t kWmcr = 0x08u;

/* MCIMX31RM Figure 37-3 / MCIMX51RM Figure 62-3. */
constexpr uint16_t kWcrReset   = 0x0030u;
constexpr uint32_t kWcrWtShift = 8u;
constexpr uint16_t kWcrWda     = 1u << 5;
constexpr uint16_t kWcrSrs     = 1u << 4;
constexpr uint16_t kWcrWde     = 1u << 2;
constexpr uint16_t kWcrWdbg    = 1u << 1;
constexpr uint16_t kWcrWdzst   = 1u << 0;

constexpr uint16_t kServiceArm    = 0x5555u;
constexpr uint16_t kServiceReload = 0xAAAAu;

constexpr uint32_t kCkilPerCount = 16384u;

enum class WdogResetSource : uint8_t { kNone, kTimeout, kSoftware };

template <uint32_t kBase, const std::string_view& kSoc>
class FreescaleWdogBase : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == kSoc;
    }

    void OnReady() override {
        clock_  = &emu_.Get<GuestCycleClock>();
        clocks_ = &emu_.Get<FreescaleTimerClocks>();
        timeout_event_ = clock_->Add([this] { OnTimeout(); });
        clock_->RegisterRateListener([this] { Retime(); });
        clock_->RegisterIdleListener([this] { OnIdle(); });
        clock_->RegisterIdleExitListener([this] { OnIdleExit(); });
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind kind) {
            OnSystemReset(kind);
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
        const uint64_t now = clock_->Cycles();
        SetRatio();
        ckil_.Anchor(now, 0u);
        OnPowerOn(now);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint8_t ReadByte(uint32_t addr) override {
        const uint16_t v = ReadReg16((addr - kBase) & ~1u);
        return static_cast<uint8_t>((addr & 1u) ? (v >> 8) : v);
    }
    uint16_t ReadHalf(uint32_t addr) override { return ReadReg16(addr - kBase); }

    void WriteByte(uint32_t addr, uint8_t value) override {
        const uint32_t off = (addr - kBase) & ~1u;
        const uint16_t old = ReadReg16(off);
        WriteReg16(off, (addr & 1u) ? static_cast<uint16_t>((old & 0x00FFu) | (value << 8))
                                    : static_cast<uint16_t>((old & 0xFF00u) | value));
    }
    void WriteHalf(uint32_t addr, uint16_t value) override { WriteReg16(addr - kBase, value); }

    void SaveState(StateWriter& w) override {
        const uint64_t now = clock_->Cycles();
        w.Write("wcr", wcr_);
        w.Write("wsr", wsr_);
        w.Write("wrsr", wrsr_);
        w.Write<uint8_t>("wcr_written", wcr_written_ ? 1u : 0u);
        w.Write<uint8_t>("service_armed", service_armed_ ? 1u : 0u);
        w.Write<uint8_t>("counting", counting_ ? 1u : 0u);
        w.Write<uint8_t>("pending_source", static_cast<uint8_t>(pending_source_));
        w.Write("timeout_tick", timeout_tick_);
        w.Write("prescaler_lag", prescaler_lag_);
        w.Write("ckil_count", ckil_.CountAt(now));
        w.Write("ckil_phase", ckil_.PhaseAt(now));
        w.Write("ckil_phase_den", ckil_.PhaseDenominator());
        SaveExtra(w);
    }

    void RestoreState(StateReader& r) override {
        uint8_t written = 0, armed = 0, counting = 0, source = 0;
        r.Read("wcr", wcr_);
        r.Read("wsr", wsr_);
        r.Read("wrsr", wrsr_);
        r.Read("wcr_written", written);
        r.Read("service_armed", armed);
        r.Read("counting", counting);
        r.Read("pending_source", source);
        r.Read("timeout_tick", timeout_tick_);
        r.Read("prescaler_lag", prescaler_lag_);
        r.Read("ckil_count", restored_count_);
        r.Read("ckil_phase", restored_phase_);
        r.Read("ckil_phase_den", restored_den_);
        wcr_written_    = written != 0u;
        service_armed_  = armed != 0u;
        counting_       = counting != 0u;
        suspended_      = false;
        pending_source_ = static_cast<WdogResetSource>(source);
        clock_->Disarm(timeout_event_);
        RestoreExtra(r);
    }

    void PostRestore() override {
        const uint64_t now = clock_->Cycles();
        SetRatio();
        ckil_.AnchorAtPhase(now, restored_count_, restored_phase_, restored_den_);
        Rearm(now);
        PostRestoreExtra();
    }

protected:
    virtual uint64_t CkilHz() const = 0;
    virtual uint16_t WcrWritable() const = 0;
    virtual uint16_t WcrWriteOnce() const = 0;
    virtual uint16_t WcrWriteOneOnce() const = 0;
    virtual void     OnWriteOnceChange(uint16_t value) = 0;
    virtual bool     SuspendedIn(FreescaleLowPowerMode mode) const = 0;
    virtual bool     SuspendStopsPrescaler() const = 0;
    virtual void     OnWdaChange() = 0;
    virtual void     OnCounterTimeout() = 0;
    virtual void     OnPowerOn(uint64_t now) = 0;
    virtual void     ResetRegisters(ResetLineKind kind, WdogResetSource source,
                                    uint64_t now) = 0;

    virtual bool ReadExtra(uint32_t, uint16_t&) { return false; }
    virtual bool WriteExtra(uint32_t, uint16_t) { return false; }
    virtual void OnReload(uint64_t) {}
    virtual void RearmExtra(uint64_t) {}
    virtual void SaveExtra(StateWriter&) {}
    virtual void RestoreExtra(StateReader&) {}
    virtual void PostRestoreExtra() {}

    void RaiseReset(WdogResetSource source) {
        pending_source_ = source;
        emu_.Get<GuestCpuReset>().WatchdogReset();
    }

    uint64_t CycleOfCount(uint32_t target, uint64_t now) const {
        return ckil_.CycleOfTick(ckil_.TicksSince(now) + (target - ckil_.CountAt(now)));
    }

    uint32_t CountAt(uint64_t now) const { return ckil_.CountAt(now); }

    GuestCycleClock* clock_  = nullptr;
    uint16_t         wcr_    = kWcrReset;
    uint16_t         wsr_    = 0u;
    uint16_t         wrsr_   = 0u;
    bool             wcr_written_ = false;
    bool             counting_    = false;
    uint32_t         timeout_tick_ = 0u;

private:
    uint16_t ReadReg16(uint32_t off) {
        switch (off) {
            case kWcr:  return wcr_;
            case kWsr:  return wsr_;
            case kWrsr: return wrsr_;
            default:    break;
        }
        uint16_t value = 0u;
        if (ReadExtra(off, value)) return value;
        HaltUnsupportedAccess("ReadReg16", kBase + off, 0);
    }

    void WriteReg16(uint32_t off, uint16_t value) {
        switch (off) {
            case kWcr: WriteWcr(value); return;
            case kWsr: WriteWsr(value); return;
            case kWrsr: break;
            default:
                if (WriteExtra(off, value)) return;
                break;
        }
        HaltUnsupportedAccess("WriteReg16", kBase + off, value);
    }

    void WriteWcr(uint16_t value) {
        if ((value & ~WcrWritable()) != 0u) {
            emu_.Get<Fatal>().Die("FreescaleWdog %08X: WCR write 0x%04X sets a reserved bit",
                                  kBase, value);
        }
        const uint16_t once = WcrWriteOnce();
        uint16_t next = value;
        if (wcr_written_ && ((value ^ wcr_) & once) != 0u) {
            OnWriteOnceChange(value);
            next = static_cast<uint16_t>((next & ~once) | (wcr_ & once));
        }
        next = static_cast<uint16_t>(next | (wcr_ & WcrWriteOneOnce()) | kWcrSrs);
        const bool enable   = (next & kWcrWde) != 0u && (wcr_ & kWcrWde) == 0u;
        const bool wda_edge = ((next ^ wcr_) & kWcrWda) != 0u;
        wcr_         = next;
        wcr_written_ = true;
        if (wda_edge) OnWdaChange();
        if (enable) Load(clock_->Cycles());
        if ((value & kWcrSrs) == 0u) RaiseReset(WdogResetSource::kSoftware);
    }

    void WriteWsr(uint16_t value) {
        wsr_ = value;
        if (value == kServiceArm) {
            service_armed_ = true;
            return;
        }
        const bool reload = value == kServiceReload && service_armed_;
        service_armed_ = false;
        if (reload && counting_) {
            const uint64_t now = clock_->Cycles();
            if (clock_->IsDue(timeout_event_, now)) return;
            Load(now);
            OnReload(now);
        }
    }

    void Load(uint64_t now) {
        const uint32_t prescaled = CountAt(now) - prescaler_lag_;
        const uint32_t next_edge = (prescaled / kCkilPerCount + 1u) * kCkilPerCount;
        timeout_tick_ = next_edge + (static_cast<uint32_t>(wcr_ >> kWcrWtShift) * kCkilPerCount) +
                        prescaler_lag_;
        counting_     = true;
        clock_->Arm(timeout_event_, CycleOfCount(timeout_tick_, now));
    }

    void OnTimeout() {
        if (!counting_) {
            emu_.Get<Fatal>().Die("FreescaleWdog %08X: time-out event fired with the counter "
                                  "idle", kBase);
        }
        counting_ = false;
        OnCounterTimeout();
    }

    void OnIdle() {
        if (!counting_ || suspended_ || !SuspendedIn(clocks_->WfiMode())) return;
        const uint64_t now = clock_->Cycles();
        if (clock_->IsDue(timeout_event_, now)) return;
        suspended_     = true;
        suspend_count_ = CountAt(now);
        clock_->Disarm(timeout_event_);
    }

    void OnIdleExit() {
        if (!suspended_) return;
        suspended_ = false;
        const uint64_t now   = clock_->Cycles();
        const uint32_t count = CountAt(now);
        uint32_t missed = 0u;
        if (SuspendStopsPrescaler()) {
            missed = count - suspend_count_;
            prescaler_lag_ += missed;
        } else {
            const uint32_t from = (suspend_count_ - prescaler_lag_) / kCkilPerCount;
            const uint32_t to   = (count - prescaler_lag_) / kCkilPerCount;
            missed = (to - from) * kCkilPerCount;
        }
        timeout_tick_ += missed;
        Rearm(now);
    }

    void OnSystemReset(ResetLineKind kind) {
        const WdogResetSource source = pending_source_;
        pending_source_ = WdogResetSource::kNone;
        if (kind == ResetLineKind::Watchdog && source == WdogResetSource::kNone) {
            emu_.Get<Fatal>().Die("FreescaleWdog %08X: a watchdog reset this unit did not "
                                  "raise", kBase);
        }
        const uint64_t now = clock_->Cycles();
        counting_      = false;
        suspended_     = false;
        service_armed_ = false;
        wcr_written_   = false;
        prescaler_lag_ = CountAt(now);
        clock_->Disarm(timeout_event_);
        ResetRegisters(kind, kind == ResetLineKind::Watchdog ? source : WdogResetSource::kNone,
                       now);
    }

    void SetRatio() {
        if (!ckil_.SetRatio(clock_->CpuHz(), CkilHz())) {
            emu_.Get<Fatal>().Die("FreescaleWdog %08X: %llu Hz CKIL against the %llu Hz core "
                                  "clock overflows", kBase,
                                  static_cast<unsigned long long>(CkilHz()),
                                  static_cast<unsigned long long>(clock_->CpuHz()));
        }
    }

    void Retime() {
        const uint64_t now = clock_->Cycles();
        if (!ckil_.Rescale(now, clock_->CpuHz(), CkilHz())) {
            emu_.Get<Fatal>().Die("FreescaleWdog %08X: CKIL rescale to the %llu Hz core clock "
                                  "overflows", kBase,
                                  static_cast<unsigned long long>(clock_->CpuHz()));
        }
        Rearm(now);
    }

    void Rearm(uint64_t now) {
        if (counting_ && !suspended_) clock_->Arm(timeout_event_, CycleOfCount(timeout_tick_, now));
        else                          clock_->Disarm(timeout_event_);
        RearmExtra(now);
    }

    const FreescaleTimerClocks* clocks_        = nullptr;
    GuestCycleClock::Event*     timeout_event_ = nullptr;
    CycleAnchoredCounter        ckil_;
    bool                        service_armed_  = false;
    bool                        suspended_      = false;
    uint32_t                    suspend_count_  = 0u;
    uint32_t                    prescaler_lag_  = 0u;
    WdogResetSource             pending_source_ = WdogResetSource::kNone;
    uint32_t                    restored_count_ = 0u;
    uint64_t                    restored_phase_ = 0u;
    uint64_t                    restored_den_   = 1u;
};

}
