#include "pr31x00_clock.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../cpu/r3000/tx39_config_register.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../jit/mips/mips_core_clock.h"
#include "../../jit/mips/mips_cpu.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "pr31x00_clock_crystal.h"

#include <cstdint>

namespace {

constexpr uint32_t kBase = 0x10C001C0u;

/* Clock Control Register (§6.3.1): CHICLKDIV[7:0]<31:24>, CHIMCLKSEL<21>, CHICLKDIR<20>,
   ENCHIMCLK<19>, ENVIDCLK<18>, ENMBUSCLK<17>, ENSPICLK<16>, ENTIMERCLK<15>, SIBMCLKDIR<13>,
   ENSIBMCLK<11>, SIBMCLKDIV[2:0]<10:8>, CSERSEL<7> reset 1, CSERDIV[2:0]<6:4>, ENCSERCLK<3>,
   ENIRCLK<2>, ENUARTACLK<1>, ENUARTBCLK<0>. Bits 23, 22 and 14 "must be zero". */
constexpr uint32_t kMustBeZero      = (1u << 23) | (1u << 22) | (1u << 14);
constexpr uint32_t kCserSel         = 1u << 7;
constexpr uint32_t kEnVidClk        = 1u << 18;
constexpr uint32_t kEnTimerClk      = 1u << 15;
constexpr uint32_t kSibMclkDir      = 1u << 13;
constexpr uint32_t kEnSibMclk       = 1u << 11;
constexpr uint32_t kSibMclkDivShift = 8u;
constexpr uint32_t kCserDivShift    = 4u;
constexpr uint32_t kDivFieldMask    = 7u;
constexpr uint32_t kDivFieldUndefined = 7u;
constexpr uint32_t kEnCserClk       = 1u << 3;

constexpr uint64_t kTimerClkDivider = 32u;

/* CSERCLK = CLK2X / 4 or FREECLK / 4 on the TMP3911BU/BXB (Tables 6.3.1 and 6.3.3). The 9.216 MHz
   boards run it: philips_nino_300 serial.dll 0x1862C7C and philips_velo_1_ce1 serial.dll 0x1EB3450
   enable the UART clock on Clock Control 0x22B0 (CSERDIV 3) for their f_UARTCLK/16 = 230400. */
constexpr uint64_t kCserPrescaler = 4u;

/* Power Control VIDRF[1:0]<28:27>, SLOWBUS<26>, DIVMOD<25>, all RESET 0 (TMPR3911
   §12.3.1 p12-12). */
constexpr uint32_t kPowerVidRfShift = 27u;
constexpr uint32_t kPowerVidRfMask  = 3u;
constexpr uint32_t kPowerSlowBus    = 1u << 26;
constexpr uint32_t kPowerDivMod     = 1u << 25;
constexpr uint32_t kPowerClockBits  =
    (kPowerVidRfMask << kPowerVidRfShift) | kPowerSlowBus | kPowerDivMod;

/* "the PLL multiplier circuit performs an x8 rate multiplication" (§6.2.2 p6-5). */
constexpr uint64_t kPllMultiplier = 8u;

}  /* namespace */

/* Clock Control RESET column: every bit 0 but CSERSEL 1 (§6.3.1 p6-6); Config RF "Value on
   Reset 00" (TMPR39xx-um Fig 6-10). */
void Pr31x00Clock::OnReady() {
    ctl_ = kCserSel;
    emu_.Get<PeripheralDispatcher>().Register(this);
    auto& config = emu_.Get<Tx39ConfigRegister>();
    config.RegisterReducedFrequencyListener([this, &config] {
        ApplyCoreRate(config.ReducedFrequency());
    });
    emu_.Get<MipsCpu>().RegisterRestoreListener([this, &config] {
        SetCoreRate(config.ReducedFrequency());
    });
    auto& reset = emu_.Get<GuestCpuReset>();
    reset.RegisterResetListener([this](ResetLineKind) {
        ctl_   = kCserSel;
        power_ = 0;
    });
    reset.RegisterResetReleaseListener([this] {
        SetCoreRate(0u);
        for (auto& fn : video_listeners_) fn();
        NotifyModuleClocks();
    });
}

/* CORECLK = F at RF 00 and SLOWBUS 0 (§6.2.1 p6-4), the reset values of Config RF (TMPR39xx-um
   Fig 6-10) and Power Control SLOWBUS (§12.3.1 p12-12). */
GuestCycleClock::Rate Pr31x00Clock::ResetCpuRate() const {
    return GuestCycleClock::Rate{PllHz(), Clk2xPerCpuClock()};
}

/* CORECLK is F, F/2, F/4, F/8 for RF 00-11 with SLOWBUS 0 (§6.2.1 p6-4). */
void Pr31x00Clock::SetCoreRate(uint32_t rf) {
    const GuestCycleClock::Rate reset = ResetCpuRate();
    emu_.Get<GuestCycleClock>().SetClockRate(GuestCycleClock::Rate{reset.num, reset.den << rf});
}

void Pr31x00Clock::ApplyCoreRate(uint32_t rf) {
    const GuestCycleClock::Rate before = VideoClockRate();
    SetCoreRate(rf);
    NotifyVideoClock(before);
    NotifyModuleClocks();
}

uint64_t Pr31x00Clock::PllHz() const {
    return emu_.Get<Pr31x00ClockCrystal>().FinHz() * kPllMultiplier;
}

uint32_t Pr31x00Clock::ReadWord(uint32_t addr) {
    if (addr == kBase) return ctl_;
    HaltUnsupportedAccess("PR31x00 CLOCK ReadWord", addr, 0);
}

void Pr31x00Clock::WriteWord(uint32_t addr, uint32_t value) {
    if (addr != kBase) HaltUnsupportedAccess("PR31x00 CLOCK WriteWord", addr, value);
    if (value & kMustBeZero) {
        HaltUnsupportedAccess("PR31x00 CLOCK reserved bits 23/22/14", addr, value);
    }
    const GuestCycleClock::Rate before = VideoClockRate();
    const uint32_t old    = ctl_;
    ctl_ = value;
    NotifyVideoClock(before);
    if (old != value) NotifyModuleClocks();
}

void Pr31x00Clock::SetPowerClockBits(uint32_t power_ctl) {
    const uint32_t bits = power_ctl & kPowerClockBits;
    if (bits & kPowerSlowBus) {
        emu_.Get<Fatal>().Die("Pr31x00Clock: Power Control 0x%08X sets SLOWBUS; the halved "
                              "internal clocks are not modeled", power_ctl);
    }
    const GuestCycleClock::Rate before = VideoClockRate();
    const uint32_t old    = power_;
    power_ = bits;
    NotifyVideoClock(before);
    if (((old ^ bits) & kPowerDivMod) != 0u) NotifyModuleClocks();
}

/* CLK2X at the CORECLK rate, CLK = CLK2X / 2, FREECLK = the PLL, XHFREE = FREECLK / 2 (TMPR3911
   §6.2.2 p6-5); DIVMOD picks CLK or XHFREE for the upper mux and CLK2X or FREECLK for the lower one
   (Figure 6.2.1 p6-3, Table 6.3.3 p6-11). */
GuestCycleClock::Rate Pr31x00Clock::Clk2xRate() const {
    const GuestCycleClock::Rate cpu = emu_.Get<GuestCycleClock>().ClockRate();
    return GuestCycleClock::Rate{cpu.num * Clk2xPerCpuClock(), cpu.den};
}

GuestCycleClock::Rate Pr31x00Clock::UpperMuxRate() const {
    if ((power_ & kPowerDivMod) != 0u) return GuestCycleClock::Rate{PllHz(), 2u};
    const GuestCycleClock::Rate clk2x = Clk2xRate();
    return GuestCycleClock::Rate{clk2x.num, clk2x.den * 2u};
}

GuestCycleClock::Rate Pr31x00Clock::LowerMuxRate() const {
    if ((power_ & kPowerDivMod) != 0u) return GuestCycleClock::Rate{PllHz(), 1u};
    return Clk2xRate();
}

GuestCycleClock::Rate Pr31x00Clock::TimerClockRate() const {
    if ((ctl_ & kEnTimerClk) == 0u) return GuestCycleClock::Rate{0u, 1u};
    const GuestCycleClock::Rate upper = UpperMuxRate();
    return GuestCycleClock::Rate{upper.num, upper.den * kTimerClkDivider};
}

/* SIBMCLKDIR 1 drives SIBMCLK out of the divider, 0 takes it from an external oscillator
   (§6.3.1 p6-7); SIBMCLKDIV 111 has no divide-modulus (p6-8, Tables 6.3.1-6.3.3). */
GuestCycleClock::Rate Pr31x00Clock::SibMasterClockRate() const {
    if ((ctl_ & kSibMclkDir) == 0u) {
        emu_.Get<Fatal>().Die("Pr31x00Clock: Clock Control 0x%08X takes SIBMCLK from an external "
                              "oscillator; that board part is not modeled", ctl_);
    }
    if ((ctl_ & kEnSibMclk) == 0u) return GuestCycleClock::Rate{0u, 1u};
    const uint32_t div = (ctl_ >> kSibMclkDivShift) & kDivFieldMask;
    if (div == kDivFieldUndefined) {
        emu_.Get<Fatal>().Die("Pr31x00Clock: Clock Control 0x%08X sets SIBMCLKDIV 111", ctl_);
    }
    const GuestCycleClock::Rate lower = LowerMuxRate();
    return GuestCycleClock::Rate{lower.num, lower.den * (div + 2u)};
}

/* CSERSEL 0 takes CSERCLK from SIBMCLK (§6.3.1 p6-8); CSERDIV 111 has no divide-modulus. */
GuestCycleClock::Rate Pr31x00Clock::UartClockRate(uint32_t uart_clock_enable) const {
    if ((ctl_ & kEnCserClk) == 0u || (ctl_ & uart_clock_enable) == 0u) {
        return GuestCycleClock::Rate{0u, 1u};
    }
    if ((ctl_ & kCserSel) == 0u) {
        emu_.Get<Fatal>().Die("Pr31x00Clock: Clock Control 0x%08X takes CSERCLK from SIBMCLK", ctl_);
    }
    const uint32_t div = (ctl_ >> kCserDivShift) & kDivFieldMask;
    if (div == kDivFieldUndefined) {
        emu_.Get<Fatal>().Die("Pr31x00Clock: Clock Control 0x%08X sets CSERDIV 111", ctl_);
    }
    const GuestCycleClock::Rate lower = LowerMuxRate();
    return GuestCycleClock::Rate{lower.num, lower.den * kCserPrescaler * (div + 2u)};
}

void Pr31x00Clock::RegisterModuleClockListener(std::function<void()> fn) {
    module_listeners_.push_back(std::move(fn));
}

void Pr31x00Clock::NotifyModuleClocks() {
    for (auto& fn : module_listeners_) fn();
}

/* TMPR3911 §12.3.1 p12-13 DIVMOD; BAUDVAL / 4 with RF 10 at DIVMOD 0: philips_nino_300 nk.exe
   sub_9F411310 and philips_velo_1_ce1 nk.exe sub_9F40E6D4; DIVMOD 1 with VIDRF 2 off PRId 0x2202:
   philips_nino_300 nk.exe 0x9F411AC0. */
GuestCycleClock::Rate Pr31x00Clock::VideoClockRate() const {
    if ((ctl_ & kEnVidClk) == 0u) return GuestCycleClock::Rate{0u, 1u};
    const GuestCycleClock::Rate upper = UpperMuxRate();
    return GuestCycleClock::Rate{upper.num,
                                 upper.den << ((power_ >> kPowerVidRfShift) & kPowerVidRfMask)};
}

void Pr31x00Clock::RegisterVideoClockListener(std::function<void()> fn) {
    video_listeners_.push_back(std::move(fn));
}

void Pr31x00Clock::NotifyVideoClock(GuestCycleClock::Rate before) {
    const GuestCycleClock::Rate now = VideoClockRate();
    if (now.num * before.den == before.num * now.den) return;
    for (auto& fn : video_listeners_) fn();
}

void Pr31x00Clock::SaveState(StateWriter& w) {
    w.Write("ctl", ctl_);
    w.Write("power_clock_bits", power_);
}

void Pr31x00Clock::RestoreState(StateReader& r) {
    r.Read("ctl", ctl_);
    r.Read("power_clock_bits", power_);
}
