#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "msm8255_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../cycle_anchored_counter.h"
#include "../guest_cpu_reset.h"
#include "../irq_controller.h"

#include <cstdint>

namespace {

/* Linux arch/arm/mach-msm/include/mach/msm_iomap-7x30.h: MSM7X30_CSR_PHYS
   0xC0100000, MSM7X30_CSR_SIZE SZ_4K; MSM_ACC_PHYS is the next 4K at
   0xC0101000. */
constexpr uint32_t kCsrBase = 0xC0100000u;
constexpr uint32_t kCsrSize = 0x00001000u;

constexpr uint32_t kGptMatch   = 0x04u;
constexpr uint32_t kGptCount   = 0x08u;
constexpr uint32_t kGptEnable  = 0x0Cu;
constexpr uint32_t kGptClear   = 0x10u;
constexpr uint32_t kDgtMatch   = 0x24u;
constexpr uint32_t kDgtCount   = 0x28u;
constexpr uint32_t kDgtEnable  = 0x2Cu;
constexpr uint32_t kDgtClear   = 0x30u;
constexpr uint32_t kDgtClkCtl  = 0x34u;
constexpr uint32_t kEnableEn   = 1u;
constexpr uint32_t kEnableClrOnMatch = 2u;
constexpr uint32_t kGptHz      = 32768u;

constexpr uint32_t kDgtSrcHz = 12288000u;

constexpr uint32_t kDgtClkCtlMax = 3u;

constexpr uint32_t kDgtClkCtlUnwritten = 0xFFFFFFFFu;

constexpr int kGptVicLine = 1;
constexpr int kDgtVicLine = 0;

const char* ChannelName(int n) { return n == 0 ? "GPT" : "DGT"; }

class Msm8255Timer : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == SocId::Msm8255;
    }

    void OnReady() override {
        clock_ = &emu_.Get<GuestCycleClock>();
        irq_   = &emu_.Get<IrqController>();
        const uint64_t now = clock_->Cycles();
        for (int n = 0; n < 2; ++n) {
            ch_[n].event = clock_->Add([this, n] { OnMatch(n); });
        }
        StartGrid(0, now);
        clock_->RegisterRateListener([this] { OnRateChange(); });
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            OnResetLine();
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kCsrBase; }
    uint32_t MmioSize() const override { return kCsrSize; }

    FastReadFn  FastReader() override { return &Msm8255Timer::FastReadThunk; }
    FastWriteFn FastWriter() override { return &Msm8255Timer::FastWriteThunk; }

    uint32_t ReadWord(uint32_t addr) override {
        return FastRead(addr - MmioBase(), 4u);
    }
    void WriteWord(uint32_t addr, uint32_t value) override {
        FastWrite(addr - MmioBase(), value, 4u);
    }

    void SaveState(StateWriter& w) override {
        const uint64_t now = Now();
        w.Write<uint32_t>("dgt_clk_ctl", dgt_clk_ctl_);
        for (int n = 0; n < 2; ++n) {
            const bool grid = DivideSelected(n);
            w.Write<uint32_t>("match", ch_[n].match);
            w.Write<uint32_t>("match_written", ch_[n].match_written ? 1u : 0u);
            w.Write<uint32_t>("enable", ch_[n].enable);
            w.Write<uint32_t>("enable_written", ch_[n].enable_written ? 1u : 0u);
            w.Write<uint32_t>("count", Count(n, now));
            w.Write<uint64_t>("grid_phase", grid ? ch_[n].counter.PhaseAt(now) : 0u);
            w.Write<uint64_t>("grid_phase_den",
                              grid ? ch_[n].counter.PhaseDenominator() : 1u);
            w.Write<uint32_t>("match_due", MatchDue(n, now) ? 1u : 0u);
        }
    }

    void RestoreState(StateReader& r) override {
        const uint64_t now = Now();
        uint32_t clk_ctl = 0;
        r.Read("dgt_clk_ctl", clk_ctl);
        if (clk_ctl > kDgtClkCtlMax && clk_ctl != kDgtClkCtlUnwritten) {
            r.Reject(
                "msm8255 timer: restored DGT_CLK_CTL 0x%08X exceeds the "
                "two-bit divide select", clk_ctl);
        }
        dgt_clk_ctl_ = clk_ctl;
        for (int n = 0; n < 2; ++n) {
            uint32_t match = 0, match_written = 0, enable = 0, enable_written = 0;
            uint32_t count = 0, due = 0;
            uint64_t phase = 0, phase_den = 0;
            r.Read("match", match);
            r.Read("match_written", match_written);
            r.Read("enable", enable);
            r.Read("enable_written", enable_written);
            r.Read("count", count);
            r.Read("grid_phase", phase);
            r.Read("grid_phase_den", phase_den);
            r.Read("match_due", due);
            if (match_written > 1u || enable_written > 1u || due > 1u) {
                r.Reject("msm8255 timer: restored %s flag word is not 0 or 1",
                         ChannelName(n));
            }
            if ((enable & ~kEnableEn) != 0u) {
                r.Reject("msm8255 timer: restored TIMER_ENABLE 0x%08X sets a bit "
                         "this timer does not model", enable);
            }
            if (enable_written == 0u && enable != 0u) {
                r.Reject("msm8255 timer: restored %s TIMER_ENABLE 0x%08X was "
                         "never written", ChannelName(n), enable);
            }
            if (match_written == 0u && match != 0u) {
                r.Reject("msm8255 timer: restored %s MATCH 0x%08X was never "
                         "written", ChannelName(n), match);
            }
            if (due != 0u && ((enable & kEnableEn) == 0u || match_written == 0u)) {
                r.Reject("msm8255 timer: restored %s carries a due match while "
                         "stopped", ChannelName(n));
            }
            if (n == 1 && (enable & kEnableEn) != 0u &&
                clk_ctl == kDgtClkCtlUnwritten) {
                r.Reject("msm8255 timer: restored DGT counts with no DGT_CLK_CTL "
                         "divide select");
            }
            ch_[n].match          = match;
            ch_[n].match_written  = match_written != 0u;
            ch_[n].enable         = enable;
            ch_[n].enable_written = enable_written != 0u;
            ch_[n].stopped_count  = count;
            if (!DivideSelected(n)) {
                if (phase != 0u || phase_den != 1u) {
                    r.Reject("msm8255 timer: restored %s carries a grid phase with no "
                             "divide select", ChannelName(n));
                }
            } else {
                ApplyRatio(n);
                if (!ch_[n].counter.AnchorAtPhase(now, count, phase, phase_den)) {
                    r.Reject("msm8255 timer: restored %s grid phase %llu/%llu is not "
                             "a fraction of one tick this build can place",
                             ChannelName(n), static_cast<unsigned long long>(phase),
                             static_cast<unsigned long long>(phase_den));
                }
            }
            if (due != 0u) ArmAt(n, now);
            else           Arm(n, now);
        }
    }

private:
    struct Channel {
        uint32_t             match          = 0;
        bool                 match_written  = false;
        uint32_t             enable         = 0;
        bool                 enable_written = false;
        uint32_t             stopped_count  = 0;
        CycleAnchoredCounter counter;
        GuestCycleClock::Event* event       = nullptr;
    };

    static uint32_t FastReadThunk(void* ctx, uint32_t off, uint32_t width) {
        return static_cast<Msm8255Timer*>(ctx)->FastRead(off, width);
    }
    static void FastWriteThunk(void* ctx, uint32_t off, uint32_t value, uint32_t width) {
        static_cast<Msm8255Timer*>(ctx)->FastWrite(off, value, width);
    }

    uint32_t FastRead(uint32_t off, uint32_t width) {
        if (width != 4u) HaltUnsupportedAccess("FastRead", MmioBase() + off, 0);
        switch (off) {
            case kGptCount:  return Count(0, Now());
            case kDgtCount:  return Count(1, Now());
            case kGptMatch:  return ReadMatch(0);
            case kDgtMatch:  return ReadMatch(1);
            case kGptEnable: return ReadEnable(0);
            case kDgtEnable: return ReadEnable(1);
            default: break;
        }
        HaltUnsupportedAccess("FastRead", MmioBase() + off, 0);
    }

    void FastWrite(uint32_t off, uint32_t value, uint32_t width) {
        if (width != 4u) HaltUnsupportedAccess("FastWrite", MmioBase() + off, value);
        const uint64_t now = Now();
        switch (off) {
            case kGptMatch:  SetMatch(0, value, now); return;
            case kDgtMatch:  SetMatch(1, value, now); return;
            case kGptEnable: SetEnable(0, value, now); return;
            case kDgtEnable: SetEnable(1, value, now); return;
            case kGptClear:  Clear(0, now); return;
            case kDgtClear:  Clear(1, now); return;
            case kDgtClkCtl: SetDgtClkCtl(value, now); return;
            default: break;
        }
        HaltUnsupportedAccess("FastWrite", MmioBase() + off, value);
    }

    uint64_t Now() { return clock_->Cycles(); }

    bool Counting(int n) const { return (ch_[n].enable & kEnableEn) != 0u; }

    bool DivideSelected(int n) const {
        return n == 0 || dgt_clk_ctl_ <= kDgtClkCtlMax;
    }

    uint32_t ReadMatch(int n) const {
        if (!ch_[n].match_written) {
            emu_.Get<Fatal>().Die(
                "msm8255 timer: %s MATCH read before any write; its power-on "
                "value is not modelled", ChannelName(n));
        }
        return ch_[n].match;
    }

    uint32_t ReadEnable(int n) const {
        if (!ch_[n].enable_written) {
            emu_.Get<Fatal>().Die(
                "msm8255 timer: %s TIMER_ENABLE read before any write; its "
                "power-on value is not modelled", ChannelName(n));
        }
        return ch_[n].enable;
    }

    void StartGrid(int n, uint64_t now) {
        ch_[n].counter.Anchor(now, 0u);
        ApplyRatio(n);
    }

    void ApplyRatio(int n) {
        if (!DivideSelected(n)) return;
        RequireRatio(n, ch_[n].counter.SetRatio(clock_->CpuHz(), TickHz(n)));
    }

    uint64_t TickHz(int n) const {
        return n == 0 ? kGptHz : kDgtSrcHz / (dgt_clk_ctl_ + 1u);
    }

    void RequireRatio(int n, bool ok) const {
        if (!ok) {
            emu_.Get<Fatal>().Die(
                "msm8255 timer: %s rate %llu Hz against the %llu Hz core "
                "overflows the 64-bit scale", ChannelName(n),
                static_cast<unsigned long long>(TickHz(n)),
                static_cast<unsigned long long>(clock_->CpuHz()));
        }
    }

    uint32_t Count(int n, uint64_t now) const {
        if (!Counting(n)) return ch_[n].stopped_count;
        return ch_[n].counter.CountAt(now);
    }

    bool MatchDue(int n, uint64_t now) const {
        return clock_->IsDue(ch_[n].event, now);
    }

    void ArmAt(int n, uint64_t cycle) {
        clock_->Arm(ch_[n].event, cycle);
    }

    void Disarm(int n) {
        clock_->Disarm(ch_[n].event);
    }

    void Arm(int n, uint64_t now) {
        if (!Counting(n) || !ch_[n].match_written) {
            Disarm(n);
            return;
        }
        ArmAt(n, ch_[n].counter.NextMatchCycle(ch_[n].match, now));
    }

    void RequireMatchAhead(int n, uint64_t now, const char* write) const {
        if (Counting(n) && ch_[n].match_written && ch_[n].match == Count(n, now)) {
            emu_.Get<Fatal>().Die(
                "msm8255 timer: %s %s leaves MATCH 0x%08X equal to the running "
                "count; whether the comparator fires on that tick is not "
                "modelled", ChannelName(n), write, ch_[n].match);
        }
    }

    void OnRateChange() {
        const uint64_t now = Now();
        for (int n = 0; n < 2; ++n) {
            if (DivideSelected(n)) {
                RequireRatio(n, ch_[n].counter.Rescale(now, clock_->CpuHz(), TickHz(n)));
            }
            Arm(n, now);
        }
    }

    void SetDgtClkCtl(uint32_t value, uint64_t now) {
        if (value > kDgtClkCtlMax) {
            emu_.Get<Fatal>().Die(
                "msm8255 timer: DGT_CLK_CTL write 0x%08X exceeds the two-bit "
                "divide select", value);
        }
        if (value == dgt_clk_ctl_) return;
        if (DivideSelected(1)) {
            emu_.Get<Fatal>().Die(
                "msm8255 timer: DGT_CLK_CTL write 0x%08X changes the divide select "
                "0x%08X; the divider phase across that change is not modelled",
                value, dgt_clk_ctl_);
        }
        dgt_clk_ctl_ = value;
        StartGrid(1, now);
    }

    void SetCount(int n, uint64_t now, uint32_t count) {
        if (Counting(n)) ch_[n].counter.SetCountAt(now, count);
        else             ch_[n].stopped_count = count;
    }

    void Clear(int n, uint64_t now) {
        SetCount(n, now, 0u);
        RequireMatchAhead(n, now, "CLEAR");
        Arm(n, now);
    }

    void SetMatch(int n, uint32_t value, uint64_t now) {
        ch_[n].match         = value;
        ch_[n].match_written = true;
        RequireMatchAhead(n, now, "MATCH write");
        Arm(n, now);
    }

    void SetEnable(int n, uint32_t value, uint64_t now) {
        if ((value & kEnableClrOnMatch) != 0u) {
            emu_.Get<Fatal>().Die(
                "msm8255 timer: %s TIMER_ENABLE_CLR_ON_MATCH_EN is not modeled "
                "(write 0x%08X)", ChannelName(n), value);
        }
        if ((value & ~(kEnableEn | kEnableClrOnMatch)) != 0u) {
            emu_.Get<Fatal>().Die(
                "msm8255 timer: %s TIMER_ENABLE write 0x%08X sets bits outside "
                "EN and CLR_ON_MATCH", ChannelName(n), value);
        }
        const bool was_counting = Counting(n);
        if (!was_counting && (value & kEnableEn) != 0u && !DivideSelected(n)) {
            emu_.Get<Fatal>().Die(
                "msm8255 timer: DGT TIMER_ENABLE write 0x%08X starts the DGT "
                "before DGT_CLK_CTL was written; its power-on divide select is "
                "not modelled", value);
        }
        const uint32_t count = Count(n, now);
        ch_[n].enable         = value;
        ch_[n].enable_written = true;
        if (was_counting == Counting(n)) return;
        SetCount(n, now, count);
        if (!was_counting) RequireMatchAhead(n, now, "TIMER_ENABLE write");
        Arm(n, now);
    }

    void Pulse(int n) {
        irq_->PulseIrq(n == 0 ? kGptVicLine : kDgtVicLine);
    }

    void OnMatch(int n) {
        if (!Counting(n)) {
            emu_.Get<Fatal>().Die(
                "msm8255 timer: %s match event fired while the channel is stopped",
                ChannelName(n));
        }
        Pulse(n);
        Arm(n, Now());
    }

    void OnResetLine() {
        dgt_clk_ctl_ = kDgtClkCtlUnwritten;
        for (int n = 0; n < 2; ++n) {
            ch_[n].match          = 0u;
            ch_[n].match_written  = false;
            ch_[n].enable         = 0u;
            ch_[n].enable_written = false;
            ch_[n].stopped_count  = 0u;
            Disarm(n);
        }
    }

    Channel          ch_[2];
    uint32_t         dgt_clk_ctl_ = kDgtClkCtlUnwritten;
    GuestCycleClock* clock_       = nullptr;
    IrqController*   irq_         = nullptr;
};

}  // namespace

REGISTER_SERVICE(Msm8255Timer);
