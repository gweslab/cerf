#include "msm8255_clock_rates.h"

#include "msm8255_value_set.h"

#include "../../boards/board_context.h"
#include "msm8255_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../state/state_stream.h"

namespace {

constexpr uint32_t kMdpCoreClock = 39u;

/* Linux arch/arm/mach-msm clock-7x30-vendor.c: clk_tbl_mdp_core, the rate
   table mdp_clk carries. */
constexpr uint32_t kMdpCoreRatesHz[] = {24576000u,  46080000u,  49152000u,
                                        52663000u,  92160000u,  122880000u,
                                        147456000u, 153600000u, 192000000u};

constexpr uint32_t kMdpCoreRateCount =
    sizeof(kMdpCoreRatesHz) / sizeof(kMdpCoreRatesHz[0]);

constexpr uint32_t kMdpVsyncClock = 43u;

/* Linux arch/arm/mach-msm clock-7x30-vendor.c: clk_tbl_mdp_vsync, whose only
   rate other than the ground source is the low-power crystal's. */
constexpr uint32_t kMdpVsyncHz = 24576000u;

/* Linux arch/arm/mach-msm clock-7x30-vendor.c: the driving rates of
   clk_tbl_mdh, the table both pmdh_clk and emdh_clk carry. */
constexpr uint32_t kMdhRatesHz[] = {49150000u,  92160000u,  122880000u,
                                    184320000u, 245760000u, 368640000u,
                                    384000000u, 445500000u};

constexpr uint32_t kMdhRateCount =
    sizeof(kMdhRatesHz) / sizeof(kMdhRatesHz[0]);

constexpr uint32_t kPmdhClock    = 115u;
constexpr uint32_t kPmdhMdhIndex = 0u;

constexpr uint32_t kPmdhBridgeClock = 116u;
constexpr uint32_t kMdpBridgeClock  = 42u;
constexpr uint32_t kAxiMdpClock     = 18u;

/* Linux arch/arm/mach-msm clock-7x30-vendor.c: pmdh_p_clk, mdp_p_clk and
   axi_mdp_clk are branch_clk gates that carry no frequency table. */
constexpr uint32_t kBridgeClockKhz = 0u;

constexpr uint32_t kMatchAtLeast = 0u;
constexpr uint32_t kMatchAtMost  = 1u;
constexpr uint32_t kMatchNearest = 2u;

constexpr uint32_t kFreqMax = 0xFFFFFFFFu;

constexpr uint32_t kHzPerKhz = 1000u;

constexpr uint32_t kRateUnavailable = 0u;

}  // namespace

REGISTER_SERVICE(Msm8255ClockRates);

bool Msm8255ClockRates::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Msm8255;
}

uint32_t Msm8255ClockRates::ReportClockFreqKhz(uint32_t clock) {
    if (clock == kMdpCoreClock) {
        const uint32_t hz =
            mdp_core_granted_hz_.load(std::memory_order_acquire);
        if (hz == kRateUnavailable) {
            emu_.Get<Fatal>().Die(
                "msm8255 clock rates: clock %u has no granted rate to report",
                clock);
        }
        return hz / kHzPerKhz;
    }
    if (clock == kMdpVsyncClock) {
        return kMdpVsyncHz / kHzPerKhz;
    }
    if (clock == kPmdhClock) {
        const uint32_t khz =
            mdh_granted_khz_[kPmdhMdhIndex].load(std::memory_order_acquire);
        if (khz == kRateUnavailable) {
            emu_.Get<Fatal>().Die(
                "msm8255 clock rates: clock %u has no granted mdh rate to "
                "report", clock);
        }
        return khz;
    }
    if (clock == kPmdhBridgeClock || clock == kMdpBridgeClock ||
        clock == kAxiMdpClock) {
        return kBridgeClockKhz;
    }
    emu_.Get<Fatal>().Die(
        "msm8255 clock rates: clock %u has no modeled rate to report", clock);
}

uint32_t Msm8255ClockRates::SelectRateHz(const uint32_t* rates, uint32_t count,
                                         uint32_t clock, uint32_t freq_hz,
                                         uint32_t match) {
    if (Msm8255ValueSetContains(rates, count, freq_hz)) {
        return freq_hz;
    }

    uint32_t above     = 0u;
    uint32_t below     = 0u;
    bool     has_above = false;
    bool     has_below = false;

    for (uint32_t i = 0; i < count; ++i) {
        const uint32_t rate = rates[i];
        if (rate > freq_hz && (!has_above || rate < above)) {
            above     = rate;
            has_above = true;
        }
        if (rate < freq_hz && (!has_below || rate > below)) {
            below     = rate;
            has_below = true;
        }
    }

    if (match == kMatchNearest) {
        if (has_above &&
            (!has_below || freq_hz - below >= above - freq_hz)) {
            return above;
        }
    } else if (match == kMatchAtLeast) {
        if (freq_hz != kFreqMax) {
            if (!has_above) {
                emu_.Get<Fatal>().Die(
                    "msm8255 clock rates: clock %u has no modeled rate at or "
                    "above the %u Hz its caller asked for", clock, freq_hz);
            }
            return above;
        }
    } else if (match != kMatchAtMost) {
        emu_.Get<Fatal>().Die(
            "msm8255 clock rates: clock %u was asked for %u Hz under match "
            "mode %u, which this program does not carry", clock, freq_hz,
            match);
    }

    if (!has_below) {
        emu_.Get<Fatal>().Die(
            "msm8255 clock rates: clock %u has no modeled rate at or below the "
            "%u Hz its caller asked for", clock, freq_hz);
    }
    return below;
}

uint32_t Msm8255ClockRates::GrantClockFreqHz(uint32_t clock, uint32_t freq_hz,
                                             uint32_t match) {
    if (clock == kMdpCoreClock) {
        if (!Msm8255ValueSetContains(kMdpCoreRatesHz, kMdpCoreRateCount,
                                     freq_hz)) {
            emu_.Get<Fatal>().Die(
                "msm8255 clock rates: clock %u has no modeled rate for a %u Hz "
                "request under match mode %u", clock, freq_hz, match);
        }
        mdp_core_granted_hz_.store(freq_hz, std::memory_order_release);
        return freq_hz;
    }
    if (clock == kPmdhClock) {
        const uint32_t rate =
            SelectRateHz(kMdhRatesHz, kMdhRateCount, clock, freq_hz, match);
        mdh_granted_khz_[kPmdhMdhIndex].store(rate / kHzPerKhz,
                                              std::memory_order_release);
        return rate;
    }
    emu_.Get<Fatal>().Die(
        "msm8255 clock rates: clock %u has no modeled rate table for a %u Hz "
        "request under match mode %u", clock, freq_hz, match);
}

uint32_t Msm8255ClockRates::GrantMdhRateKhz(uint32_t index, uint32_t min_khz,
                                            uint32_t max_khz) {
    if (index >= kMsm8255MdhIndexCount) {
        emu_.Get<Fatal>().Die(
            "msm8255 clock rates: mdh clock index %u is outside the %u the "
            "rate table serves", index, kMsm8255MdhIndexCount);
    }

    uint32_t granted = kRateUnavailable;
    for (uint32_t i = 0; i < kMdhRateCount; ++i) {
        const uint32_t khz = kMdhRatesHz[i] / kHzPerKhz;
        if (khz >= min_khz && khz <= max_khz && khz > granted) {
            granted = khz;
        }
    }
    mdh_granted_khz_[index].store(granted, std::memory_order_release);
    return granted;
}

void Msm8255ClockRates::SaveState(StateWriter& w) const {
    for (const auto& rate : mdh_granted_khz_) {
        w.Write<uint32_t>("rate", rate.load(std::memory_order_acquire));
    }
    w.Write<uint32_t>("mdp_core_granted_hz", mdp_core_granted_hz_.load(std::memory_order_acquire));
}

void Msm8255ClockRates::RestoreState(StateReader& r) {
    for (auto& rate : mdh_granted_khz_) {
        uint32_t khz = kRateUnavailable;
        r.Read("rate", khz);
        rate.store(khz, std::memory_order_release);
    }
    uint32_t hz = kRateUnavailable;
    r.Read("mdp_core_granted_hz", hz);
    mdp_core_granted_hz_.store(hz, std::memory_order_release);
}
