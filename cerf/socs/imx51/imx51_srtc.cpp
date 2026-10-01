#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../host/guest_deep_sleep.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "../irq_controller.h"
#include "../oscillator_ticks.h"
#include "imx51_clock_input.h"
#include "imx51_id.h"

#include <array>
#include <cstdint>

namespace {

constexpr uint32_t kBase = 0x73FA4000u;
constexpr uint32_t kSize = 0x00001000u;
constexpr uint32_t kIrq  = 24u;

constexpr uint32_t kOffLpscmr = 0x00u;
constexpr uint32_t kOffLpsclr = 0x04u;
constexpr uint32_t kOffLpsar  = 0x08u;
constexpr uint32_t kOffLpcr   = 0x10u;
constexpr uint32_t kOffLpsr   = 0x14u;

/* Genesi i.MX5 Linux rtc-mxc_v2.c SRTC_LPSCLR_LLPSC_LSH and its
   (LPSCMR << 32 | LPSCLR) >> 17 time read. */
constexpr uint32_t kLpsclrShift    = 17u;
constexpr uint32_t kLpsclrReserved = 0x0001FFFFu;
constexpr uint32_t kFractionBits   = 15u;
constexpr uint64_t kFractionMask   = 0x7FFFu;

/* MCIMX51RM §55.1.1: non-rollover 47-bit time counter. */
constexpr uint64_t kCountMax = 0x7FFFFFFFFFFFull;

/* Genesi i.MX5 Linux rtc-mxc_v2.c SRTC_LPCR_EN_LP, SRTC_LPCR_ALP, SRTC_LPSR_ALP. */
constexpr uint32_t kLpcrEnLp = 1u << 3;
constexpr uint32_t kLpcrAlp  = 1u << 7;
constexpr uint32_t kLpsrAlp  = 1u << 3;

/* Genesi i.MX5 Linux rtc-mxc_v2.c rtc_write_sync_lp: "all writes from the IP domain will be
   synchronized to the CKIL domain", "Wait for 3 CKIL cycles". */
constexpr uint64_t kSyncEdges  = 3u;
constexpr uint32_t kPendingMax = 5u;
constexpr uint64_t kNever      = ~0ull;

class Imx51Srtc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == SocId::Imx51;
    }

    /* MCIMX51RM §55.1.3: a 47-bit counter on 32.768 kHz; continuous time is kept during
       power down system states. */
    void OnReady() override {
        clock_ = &emu_.Get<GuestCycleClock>();
        event_ = clock_->Add([this] { Update(); });
        ckil_.Attach(emu_.Get<Imx51ClockInput>().CkilHz(), 1u);
        clock_->RegisterRateListener([this] {
            ckil_.Rescale();
            Update();
        });
        emu_.Get<GuestDeepSleep>().RegisterParkClock([this] { Update(); });
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind kind) {
            if (kind == ResetLineKind::Rtc) PowerOnReset();
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override {
        Update();
        switch (addr - kBase) {
            case kOffLpscmr: return static_cast<uint32_t>(Count() >> kFractionBits);
            case kOffLpsclr:
                return static_cast<uint32_t>(Count() & kFractionMask) << kLpsclrShift;
            case kOffLpcr:   return lpcr_;
            default:         break;
        }
        emu_.Get<Fatal>().Die("Imx51Srtc: read of +0x%03X is not modeled", addr - kBase);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        Update();
        const uint32_t off = addr - kBase;
        switch (off) {
            case kOffLpscmr:
            case kOffLpsar:
                break;
            case kOffLpsclr:
                if ((value & kLpsclrReserved) != 0u) {
                    emu_.Get<Fatal>().Die("Imx51Srtc: LPSCLR write 0x%08X sets reserved bits",
                                          value);
                }
                break;
            case kOffLpcr:
                if ((value & ~(kLpcrEnLp | kLpcrAlp)) != 0u) {
                    emu_.Get<Fatal>().Die("Imx51Srtc: LPCR write 0x%08X sets a control bit that "
                                          "is not modeled", value);
                }
                break;
            case kOffLpsr:
                if ((value & ~kLpsrAlp) != 0u) {
                    emu_.Get<Fatal>().Die("Imx51Srtc: LPSR write 0x%08X clears a status bit that "
                                          "is not modeled", value);
                }
                break;
            default:
                emu_.Get<Fatal>().Die("Imx51Srtc: write 0x%08X to +0x%03X is not modeled",
                                      value, off);
        }
        Schedule(off, value);
        Update();
    }

    void SaveState(StateWriter& w) override {
        CatchUp();
        ckil_.Save(w);
        const uint64_t now = ckil_.Now();
        std::array<uint32_t, kPendingMax> off{};
        std::array<uint32_t, kPendingMax> value{};
        std::array<uint64_t, kPendingMax> left{};
        for (uint32_t i = 0; i < pending_n_; ++i) {
            off[i]   = pending_[i].off;
            value[i] = pending_[i].value;
            left[i]  = pending_[i].land - now;
        }
        w.Write<uint64_t>("lp_count", Count());
        w.Write<uint32_t>("lpcr", lpcr_);
        w.Write<uint32_t>("lpsar", lpsar_);
        w.Write<uint8_t>("alp", alp_ ? 1u : 0u);
        w.Write<uint8_t>("alp_unknown", alp_unknown_ ? 1u : 0u);
        w.WriteBytes("lp_sync_off", off.data(), sizeof(off));
        w.WriteBytes("lp_sync_value", value.data(), sizeof(value));
        w.WriteBytes("lp_sync_ticks_left", left.data(), sizeof(left));
    }

    void RestoreState(StateReader& r) override {
        uint64_t count = 0;
        uint32_t lpcr = 0, lpsar = 0;
        uint8_t  alp = 0, alp_unknown = 0;
        std::array<uint32_t, kPendingMax> off{};
        std::array<uint32_t, kPendingMax> value{};
        std::array<uint64_t, kPendingMax> left{};
        ckil_.Restore(r);
        r.Read("lp_count", count);
        r.Read("lpcr", lpcr);
        r.Read("lpsar", lpsar);
        r.Read("alp", alp);
        r.Read("alp_unknown", alp_unknown);
        r.ReadBytes("lp_sync_off", off.data(), sizeof(off));
        r.ReadBytes("lp_sync_value", value.data(), sizeof(value));
        r.ReadBytes("lp_sync_ticks_left", left.data(), sizeof(left));
        const uint64_t now = ckil_.Now();
        count_at_set_ = count;
        ckil_at_set_  = now;
        lpcr_         = lpcr;
        lpsar_        = lpsar;
        alp_          = alp != 0u;
        alp_unknown_  = alp_unknown != 0u;
        pending_n_    = 0u;
        while (pending_n_ < kPendingMax && left[pending_n_] != 0u) {
            pending_[pending_n_] = Pending{off[pending_n_], value[pending_n_],
                                           now + left[pending_n_]};
            ++pending_n_;
        }
        clock_->Disarm(event_);
    }

    void PostRestore() override { Update(); }

private:
    struct Pending {
        uint32_t off;
        uint32_t value;
        uint64_t land;
    };

    /* MCIMX51RM Table 54-10: only the POR and jtag_rst_b rows assert srtc_rst_b. */
    void PowerOnReset() {
        SetCountAt(ckil_.Now(), 0u);
        lpcr_        = 0u;
        lpsar_       = 0u;
        alp_         = false;
        alp_unknown_ = false;
        pending_n_   = 0u;
        clock_->Disarm(event_);
        DriveIrq();
    }

    bool Running() const { return (lpcr_ & kLpcrEnLp) != 0u; }

    uint64_t CountAt(uint64_t tick) {
        const uint64_t count = count_at_set_ + (Running() ? tick - ckil_at_set_ : 0u);
        if (count >= kCountMax) {
            emu_.Get<Fatal>().Die("Imx51Srtc: the LP counter reached 0x%llX; the time rollover "
                                  "failure state is not modeled",
                                  static_cast<unsigned long long>(count));
        }
        return count;
    }

    uint64_t Count() { return CountAt(ckil_.Now()); }

    void SetCountAt(uint64_t tick, uint64_t count) {
        count_at_set_ = count;
        ckil_at_set_  = tick;
    }

    /* sync_2 nk.exe sub_8010367C and Genesi i.MX5 Linux rtc-mxc_v2.c rtc_update_alarm
       write the alarm second itself to LPSAR. */
    uint64_t AlarmCount() const {
        return static_cast<uint64_t>(lpsar_) << kFractionBits;
    }

    /* sync_2 nk.exe sub_8010367C: LPSR.ALP clear at 0x80103724, LPCR.ALP set at 0x80103730,
       LPSAR at 0x80103734, SYSINTR 13 enable at 0x80103740. */
    uint64_t MatchTick() const {
        if (alp_ || !Running() || AlarmCount() <= count_at_set_) return kNever;
        return ckil_at_set_ + (AlarmCount() - count_at_set_);
    }

    /* sync_2 nk.exe sub_80103590: LPSCLR = 0 at 0x80103638, LPSCMR at 0x8010363C, then three
       passes that wait for LPSCLR to change (0x80103640-0x80103654). */
    void Schedule(uint32_t off, uint32_t value) {
        for (uint32_t i = 0; i < pending_n_; ++i) {
            if (pending_[i].off != off) continue;
            emu_.Get<Fatal>().Die("Imx51Srtc: write 0x%08X to +0x%03X while its write 0x%08X is "
                                  "still in its %llu-edge CKIL synchronization window", value,
                                  off, pending_[i].value,
                                  static_cast<unsigned long long>(kSyncEdges));
        }
        pending_[pending_n_++] = Pending{off, value, ckil_.Now() + kSyncEdges};
    }

    void Land(const Pending& p) {
        SetCountAt(p.land, CountAt(p.land));
        switch (p.off) {
            case kOffLpscmr:
                count_at_set_ = (static_cast<uint64_t>(p.value) << kFractionBits) |
                                (count_at_set_ & kFractionMask);
                return;
            case kOffLpsclr:
                count_at_set_ = (count_at_set_ & ~kFractionMask) | (p.value >> kLpsclrShift);
                return;
            case kOffLpsar:
                lpsar_ = p.value;
                return;
            case kOffLpcr:
                lpcr_ = p.value;
                return;
            default:
                if ((p.value & kLpsrAlp) != 0u) {
                    alp_         = false;
                    alp_unknown_ = false;
                }
                return;
        }
    }

    void CatchUp() {
        const uint64_t now = ckil_.Now();
        for (;;) {
            const uint64_t land  = pending_n_ != 0u ? pending_[0].land : kNever;
            const uint64_t match = MatchTick();
            const uint64_t next  = land < match ? land : match;
            if (next > now) return;
            if (land == match) {
                emu_.Get<Fatal>().Die("Imx51Srtc: a write to +0x%03X lands on the CKIL edge where "
                                      "LPSAR 0x%08X matches; their order is not modeled",
                                      pending_[0].off, lpsar_);
            }
            if (match < land) {
                alp_ = true;
                continue;
            }
            Land(pending_[0]);
            for (uint32_t i = 1; i < pending_n_; ++i) pending_[i - 1u] = pending_[i];
            --pending_n_;
        }
    }

    void Update() {
        CatchUp();
        if (!alp_ && lpsar_ == (Count() >> kFractionBits)) alp_unknown_ = true;
        if (alp_unknown_ && (lpcr_ & kLpcrAlp) != 0u) {
            emu_.Get<Fatal>().Die("Imx51Srtc: LPCR.ALP is set while LPSAR 0x%08X equals the "
                                  "current second and LPSR.ALP is clear; whether a match inside "
                                  "that second sets LPSR.ALP is not modeled", lpsar_);
        }
        DriveIrq();
        const uint64_t land  = pending_n_ != 0u ? pending_[0].land : kNever;
        const uint64_t match = MatchTick();
        const uint64_t next  = land < match ? land : match;
        if (next == kNever) {
            clock_->Disarm(event_);
        } else {
            ckil_.ArmAt(event_, next);
        }
    }

    /* Genesi i.MX5 Linux rtc-mxc_v2.c mxc_rtc_interrupt: the LP alarm interrupts while
       LPSR.ALP and LPCR.ALP. */
    void DriveIrq() {
        auto& irq = emu_.Get<IrqController>();
        if (alp_ && (lpcr_ & kLpcrAlp) != 0u) {
            irq.AssertIrq(kIrq);
        } else {
            irq.DeAssertIrq(kIrq);
        }
    }

    GuestCycleClock*                 clock_ = nullptr;
    GuestCycleClock::Event*          event_ = nullptr;
    OscillatorTicks                  ckil_{emu_, true};
    uint64_t                         ckil_at_set_  = 0u;
    uint64_t                         count_at_set_ = 0u;
    uint32_t                         lpcr_         = 0u;
    uint32_t                         lpsar_        = 0u;
    bool                             alp_          = false;
    bool                             alp_unknown_  = false;
    std::array<Pending, kPendingMax> pending_{};
    uint32_t                         pending_n_    = 0u;
};

}

REGISTER_SERVICE(Imx51Srtc);
