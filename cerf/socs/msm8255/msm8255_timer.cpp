#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "msm8255_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/virtual_clock.h"
#include "../../core/virtual_timer_list.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../free_run_counter.h"
#include "../guest_cpu_reset.h"
#include "../irq_controller.h"

#include <atomic>
#include <cstdint>
#include <mutex>

namespace {

using cerf_free_run_counter::FreeRunCounter;
using cerf_free_run_counter::TickScale;

/* Linux arch/arm/mach-msm/include/mach/msm_iomap-7x30.h: MSM7X30_CSR_PHYS
   0xC0100000, MSM7X30_CSR_SIZE SZ_4K; MSM_ACC_PHYS is the next 4K at
   0xC0101000. */
constexpr uint32_t kCsrBase = 0xC0100000u;
constexpr uint32_t kCsrSize = 0x00001000u;

/* Ganbold Tsagaankhuu's FreeBSD Qualcomm MSM timer driver, timer.c:
   DGT_ENABLE_EN 1, DGT_ENABLE_CLR_ON_MATCH_EN 2, GPT_TIMER_CLKSRC 32768. */
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

/* The same FreeBSD timer.c: enum { DGT_CLK_CTL_DIV_1 = 0, DGT_CLK_CTL_DIV_2 = 1,
   DGT_CLK_CTL_DIV_3 = 2, DGT_CLK_CTL_DIV_4 = 3 }. */
constexpr uint32_t kDgtClkCtlMax = 3u;

constexpr uint32_t kDgtClkCtlUnwritten = 0xFFFFFFFFu;

constexpr int kGptVicLine = 1;
constexpr int kDgtVicLine = 0;

constexpr TickScale kGptScale{kGptHz};
constexpr TickScale kDgtScales[kDgtClkCtlMax + 1u] = {
    TickScale(kDgtSrcHz / 1u),
    TickScale(kDgtSrcHz / 2u),
    TickScale(kDgtSrcHz / 3u),
    TickScale(kDgtSrcHz / 4u),
};

class Msm8255Timer : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == SocId::Msm8255;
    }

    void OnReady() override {
        auto& timers = emu_.Get<VirtualTimerList>();
        const int64_t now = NowNs();
        for (int n = 0; n < 2; ++n) {
            ch_[n].entry = timers.Add([this, n] { OnMatch(n); });
            ch_[n].counter.Set(now, 0u);
        }
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            std::lock_guard<std::mutex> g(mtx_);
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
        std::lock_guard<std::mutex> g(mtx_);
        const int64_t now = NowNs();
        w.Write<uint32_t>("dgt_clk_ctl", dgt_clk_ctl_.load(std::memory_order_acquire));
        for (int n = 0; n < 2; ++n) {
            w.Write<uint32_t>("match", ch_[n].match.load(std::memory_order_acquire));
            w.Write<uint32_t>("enable", ch_[n].enable.load(std::memory_order_acquire));
            w.Write<uint32_t>("count", CountAt(ch_[n], n, now));
        }
    }

    void RestoreState(StateReader& r) override {
        std::lock_guard<std::mutex> g(mtx_);
        const int64_t now = NowNs();
        uint32_t clk_ctl = 0;
        r.Read("dgt_clk_ctl", clk_ctl);
        if (clk_ctl > kDgtClkCtlMax && clk_ctl != kDgtClkCtlUnwritten) {
            r.Reject(
                "msm8255 timer: restored DGT_CLK_CTL 0x%08X exceeds the "
                "two-bit divide select", clk_ctl);
        }
        dgt_clk_ctl_.store(clk_ctl, std::memory_order_release);
        for (int n = 0; n < 2; ++n) {
            uint32_t match = 0, enable = 0, count = 0;
            r.Read("match", match);
            r.Read("enable", enable);
            r.Read("count", count);
            ch_[n].match.store(match, std::memory_order_release);
            ch_[n].enable.store(enable, std::memory_order_release);
            ch_[n].frozen.store(count, std::memory_order_release);
            ch_[n].counter.Set(now, count);
            Arm(ch_[n], n, now);
        }
    }

private:
    struct Channel {
        FreeRunCounter counter;
        std::atomic<uint32_t> match{0};
        std::atomic<uint32_t> enable{0};
        std::atomic<uint32_t> frozen{0};
        VirtualTimerList::Entry* entry = nullptr;
    };

    const TickScale& ScaleFor(int n) const {
        if (n == 0) return kGptScale;
        const uint32_t sel = dgt_clk_ctl_.load(std::memory_order_acquire);
        if (sel > kDgtClkCtlMax) {
            emu_.Get<Fatal>().Die(
                "msm8255 timer: the DGT is counting before DGT_CLK_CTL was "
                "written; its power-on divide select is not modelled");
        }
        return kDgtScales[sel];
    }

    static uint32_t FastReadThunk(void* ctx, uint32_t off, uint32_t width) {
        return static_cast<Msm8255Timer*>(ctx)->FastRead(off, width);
    }
    static void FastWriteThunk(void* ctx, uint32_t off, uint32_t value, uint32_t width) {
        static_cast<Msm8255Timer*>(ctx)->FastWrite(off, value, width);
    }

    uint32_t FastRead(uint32_t off, uint32_t width) {
        if (width != 4u) HaltUnsupportedAccess("FastRead", MmioBase() + off, 0);
        switch (off) {
            case kGptCount:  return CountAt(ch_[0], 0, NowNs());
            case kDgtCount:  return CountAt(ch_[1], 1, NowNs());
            case kGptMatch:  return ch_[0].match.load(std::memory_order_acquire);
            case kDgtMatch:  return ch_[1].match.load(std::memory_order_acquire);
            case kGptEnable: return ch_[0].enable.load(std::memory_order_acquire);
            case kDgtEnable: return ch_[1].enable.load(std::memory_order_acquire);
            default: break;
        }
        HaltUnsupportedAccess("FastRead", MmioBase() + off, 0);
    }

    void FastWrite(uint32_t off, uint32_t value, uint32_t width) {
        if (width != 4u) HaltUnsupportedAccess("FastWrite", MmioBase() + off, value);
        std::lock_guard<std::mutex> g(mtx_);
        const int64_t now = NowNs();
        switch (off) {
            case kGptMatch: SetMatch(ch_[0], 0, value, now); return;
            case kDgtMatch: SetMatch(ch_[1], 1, value, now); return;
            case kGptEnable: SetEnable(ch_[0], 0, value, now); return;
            case kDgtEnable: SetEnable(ch_[1], 1, value, now); return;
            case kGptClear: SetCount(ch_[0], 0, 0u, now); return;
            case kDgtClear: SetCount(ch_[1], 1, 0u, now); return;
            case kDgtClkCtl: {
                if (value > kDgtClkCtlMax) {
                    emu_.Get<Fatal>().Die(
                        "msm8255 timer: DGT_CLK_CTL write 0x%08X exceeds the "
                        "two-bit divide select", value);
                }
                const uint32_t count = CountAt(ch_[1], 1, now);
                dgt_clk_ctl_.store(value, std::memory_order_release);
                Reanchor(ch_[1], 1, count, now);
                return;
            }
            default: break;
        }
        HaltUnsupportedAccess("FastWrite", MmioBase() + off, value);
    }

    int64_t NowNs() const { return emu_.Get<VirtualClock>().NowNs(); }

    uint32_t CountAt(const Channel& c, int n, int64_t now) const {
        if ((c.enable.load(std::memory_order_acquire) & kEnableEn) == 0u) {
            return c.frozen.load(std::memory_order_acquire);
        }
        return c.counter.At(now, ScaleFor(n));
    }

    void Reanchor(Channel& c, int n, uint32_t count, int64_t now) {
        c.frozen.store(count, std::memory_order_release);
        c.counter.Set(now, count);
        Arm(c, n, now);
    }

    void SetCount(Channel& c, int n, uint32_t count, int64_t now) {
        DropIrq(n);
        Reanchor(c, n, count, now);
    }

    void SetMatch(Channel& c, int n, uint32_t value, int64_t now) {
        c.match.store(value, std::memory_order_release);
        DropIrq(n);
        Arm(c, n, now);
    }

    void DropIrq(int n) {
        emu_.Get<IrqController>().DeAssertIrq(n == 0 ? kGptVicLine : kDgtVicLine);
    }

    void SetEnable(Channel& c, int n, uint32_t value, int64_t now) {
        if ((value & kEnableClrOnMatch) != 0u) {
            emu_.Get<Fatal>().Die(
                "msm8255 timer: %s TIMER_ENABLE_CLR_ON_MATCH_EN is not modeled "
                "(write 0x%08X)", n == 0 ? "GPT" : "DGT", value);
        }
        if ((value & ~(kEnableEn | kEnableClrOnMatch)) != 0u) {
            emu_.Get<Fatal>().Die(
                "msm8255 timer: %s TIMER_ENABLE write 0x%08X sets bits outside "
                "EN and CLR_ON_MATCH", n == 0 ? "GPT" : "DGT", value);
        }
        const bool was_on = (c.enable.load(std::memory_order_acquire) & kEnableEn) != 0u;
        const bool now_on = (value & kEnableEn) != 0u;
        if (was_on && !now_on) {
            c.frozen.store(c.counter.At(now, ScaleFor(n)), std::memory_order_release);
        } else if (!was_on && now_on) {
            c.counter.Set(now, c.frozen.load(std::memory_order_acquire));
        }
        c.enable.store(value, std::memory_order_release);
        Arm(c, n, now);
    }

    void Arm(Channel& c, int n, int64_t now) {
        if ((c.enable.load(std::memory_order_acquire) & kEnableEn) == 0u) {
            c.entry->Arm(VirtualTimerList::kNoDeadline);
            return;
        }
        c.entry->Arm(ScaleFor(n).NextMatchNs(
            c.match.load(std::memory_order_acquire), CountAt(c, n, now), now));
    }

    void OnMatch(int n) {
        std::lock_guard<std::mutex> g(mtx_);
        Channel& c = ch_[n];
        if (c.entry->DeadlineNs() != VirtualTimerList::kNoDeadline) return;
        if ((c.enable.load(std::memory_order_acquire) & kEnableEn) == 0u) return;
        const int64_t  now   = NowNs();
        const uint32_t match = c.match.load(std::memory_order_acquire);
        if (static_cast<int32_t>(match - CountAt(c, n, now)) > 0) {
            Arm(c, n, now);
            return;
        }
        emu_.Get<IrqController>().AssertIrq(n == 0 ? kGptVicLine : kDgtVicLine);
    }

    void OnResetLine() {
        dgt_clk_ctl_.store(kDgtClkCtlUnwritten, std::memory_order_release);
        const int64_t now = NowNs();
        for (int n = 0; n < 2; ++n) {
            ch_[n].match.store(0u, std::memory_order_release);
            ch_[n].enable.store(0u, std::memory_order_release);
            SetCount(ch_[n], n, 0u, now);
        }
    }

    std::mutex mtx_;
    Channel    ch_[2];
    std::atomic<uint32_t> dgt_clk_ctl_{kDgtClkCtlUnwritten};
};

}  // namespace

REGISTER_SERVICE(Msm8255Timer);
