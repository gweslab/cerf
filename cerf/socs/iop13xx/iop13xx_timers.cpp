#include "iop13xx_timers.h"

#include "iop13xx_clocks.h"
#include "iop13xx_cp6_registers.h"
#include "iop13xx_id.h"
#include "iop13xx_watchdog.h"
#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "../irq_controller.h"

namespace {

/* Intel 81341/81342 Developer's Manual Table 496 (printed p. 814): TMRx tc
   [0], enable [1], reload [2], pri [3], csel [5:4]; [31:6] reserved. */
constexpr uint32_t kModeTc        = 1u << 0;
constexpr uint32_t kModeEnable    = 1u << 1;
constexpr uint32_t kModeReload    = 1u << 2;
constexpr uint32_t kModePri       = 1u << 3;
constexpr uint32_t kModeCselShift = 4u;
constexpr uint32_t kModeCselMask  = 3u << kModeCselShift;
constexpr uint32_t kModeReserved  = ~0x3Fu;

/* Table 500 (printed p. 818): TISR watchdog [2], timer 1 [1], timer 0 [0]. */
constexpr uint32_t kTisrTimers   = 0x3u;
constexpr uint32_t kTisrWatchdog = 1u << 2;
constexpr uint32_t kTisrMask     = 0x7u;

/* Table 467 (printed p. 768): INTCTL0 timer 0 [8], timer 1 [9]. */
constexpr int kSourceOfTimer[2] = {8, 9};

constexpr uint64_t kTerminalAgeNone = 2u;

struct ChannelNames {
    const char* mode;
    const char* reload;
    const char* count;
    const char* terminal_age;
    const char* stuck_zero;
    const char* phase;
    const char* phase_den;
};

constexpr ChannelNames kChannelNames[2] = {
    {"timer0_mode", "timer0_reload", "timer0_count", "timer0_terminal_age",
     "timer0_stuck_zero", "timer0_phase", "timer0_phase_den"},
    {"timer1_mode", "timer1_reload", "timer1_count", "timer1_terminal_age",
     "timer1_stuck_zero", "timer1_phase", "timer1_phase_den"},
};

}

bool Iop13xxTimers::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Iop13xx;
}

void Iop13xxTimers::OnReady() {
    clock_    = &emu_.Get<GuestCycleClock>();
    watchdog_ = &emu_.Get<Iop13xxWatchdog>();
    for (Channel& ch : timer_) {
        Channel* channel = &ch;
        ch.event = clock_->Add([this, channel] { OnChannelEvent(*channel); });
    }
    ResetState();
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) return;
        ResetState();
    });
}

bool Iop13xxTimers::IsTimerKey(uint32_t key) {
    return (key & ~0xFu) == Iop13xxCp6Key(0, 9) && (key & 0xFu) <= 8u;
}

/* Table 497 (printed p. 816): TCLOCK is the internal bus clock divided by
   1, 4, 8 or 16. */
uint64_t Iop13xxTimers::Divisor(uint32_t mode) {
    constexpr uint64_t kDivisor[4] = {1u, 4u, 8u, 16u};
    return kDivisor[(mode & kModeCselMask) >> kModeCselShift];
}

uint64_t Iop13xxTimers::CyclesPerTick(uint32_t mode) {
    return kIop13xxCoreCyclesPerBusClock * Divisor(mode);
}

/* Figure 117 (printed p. 812) and Table 493 (printed p. 810): after TCRx
   reaches 0 the TRRx-to-TCRx transfer takes one internal bus clock, which is a
   whole TCLOCK only at the 1:1 select. */
uint64_t Iop13xxTimers::ReloadDelay(uint32_t mode) { return Divisor(mode) == 1u ? 1u : 0u; }

bool Iop13xxTimers::Running(const Channel& ch) { return (ch.mode & kModeEnable) != 0u; }

bool Iop13xxTimers::AtTerminalTick(Channel& ch, uint64_t cycle) {
    return ch.has_last && ch.counter.TicksSince(cycle) == ch.last_terminal;
}

bool Iop13xxTimers::InReloadWindow(Channel& ch, uint64_t cycle) {
    if (!ch.has_last) return false;
    const uint64_t k = ch.counter.TicksSince(cycle);
    if (ReloadDelay(ch.mode) != 0u) return k == ch.last_terminal || k == ch.last_terminal + 1u;
    return k == ch.last_terminal &&
           ch.counter.PhaseAt(cycle) * Divisor(ch.mode) < ch.counter.PhaseDenominator();
}

unsigned Iop13xxTimers::Index(const Channel& ch) const {
    return static_cast<unsigned>(&ch - timer_);
}

uint32_t Iop13xxTimers::StatusBit(const Channel& ch) const { return 1u << Index(ch); }

bool Iop13xxTimers::SetTickRatio(Channel& ch) {
    return ch.counter.SetRatio(CyclesPerTick(ch.mode), 1u);
}

void Iop13xxTimers::RatioOverflow(const Channel& ch) {
    emu_.Get<Fatal>().Die("IOP13xx timer %u: %llu core cycles per TCLOCK overflow the cycle "
                          "ratio", Index(ch), static_cast<unsigned long long>(CyclesPerTick(ch.mode)));
}

void Iop13xxTimers::StopAtTerminal(Channel& ch) {
    tisr_ |= StatusBit(ch);
    ch.mode          = (ch.mode | kModeTc) & ~kModeEnable;
    ch.stopped_count = 0;
}

/* Section 12.1.1 (printed p. 808) and Table 503 (printed p. 820). */
void Iop13xxTimers::Load(Channel& ch, uint64_t tick, uint32_t count) {
    ch.has_last   = false;
    ch.stuck_zero = false;
    if (count != 0u) {
        ch.next_terminal = tick + count;
        return;
    }
    if ((ch.mode & kModeReload) == 0u) {
        StopAtTerminal(ch);
        return;
    }
    if (ch.reload == 0u) {
        ch.stuck_zero = true;
        return;
    }
    emu_.Get<Fatal>().Die("IOP13xx timer %u: auto-reload with TCRx 0 and TRRx 0x%08X, a "
                          "condition Table 503 does not define", Index(ch), ch.reload);
}

bool Iop13xxTimers::Advance(Channel& ch, uint64_t cycle) {
    if (!Running(ch) || ch.stuck_zero) return false;
    const uint64_t k = ch.counter.TicksSince(cycle);
    if (k < ch.next_terminal) return false;
    if ((ch.mode & kModeReload) == 0u) {
        StopAtTerminal(ch);
        return true;
    }
    tisr_ |= StatusBit(ch);
    if (ch.reload == 0u) {
        ch.stuck_zero = true;
        return true;
    }
    const uint64_t period = static_cast<uint64_t>(ch.reload) + ReloadDelay(ch.mode);
    ch.last_terminal = ch.next_terminal + (k - ch.next_terminal) / period * period;
    ch.has_last      = true;
    ch.next_terminal = ch.last_terminal + period;
    return true;
}

uint32_t Iop13xxTimers::CountAt(Channel& ch, uint64_t cycle) {
    if (Advance(ch, cycle)) Arm(ch);
    if (!Running(ch)) return ch.stopped_count;
    if (ch.stuck_zero) return 0u;
    if (ReloadDelay(ch.mode) != 0u && AtTerminalTick(ch, cycle)) return 0u;
    return static_cast<uint32_t>(ch.next_terminal - ch.counter.TicksSince(cycle));
}

/* Section 12.2 (printed p. 811): a second request before the CPU services the
   first may be lost; software clears the pending request by writing a 1 to TISR. */
void Iop13xxTimers::Arm(Channel& ch) {
    if (!Running(ch) || ch.stuck_zero || (tisr_ & StatusBit(ch)) != 0u) {
        clock_->Disarm(ch.event);
        return;
    }
    clock_->Arm(ch.event, ch.counter.CycleOfTick(ch.next_terminal));
}

/* Section 12.1.1 (printed p. 808): TMRx.tc stays set until software reads or
   writes TMRx; either access clears it, and a write ignores the written tc. */
uint32_t Iop13xxTimers::ReadMode(Channel& ch, uint64_t cycle) {
    if (Advance(ch, cycle)) Arm(ch);
    const uint32_t value = ch.mode;
    ch.mode &= ~kModeTc;
    return value;
}

void Iop13xxTimers::WriteMode(Channel& ch, uint32_t value, uint64_t cycle) {
    if (Advance(ch, cycle)) Arm(ch);
    if ((value & kModeReserved) != 0u) {
        emu_.Get<Fatal>().Die("IOP13xx TMR%u write 0x%08X sets reserved bits [31:6]",
                              Index(ch), value);
    }
    if ((value & kModePri) != 0u) {
        emu_.Get<Fatal>().Die("IOP13xx TMR%u write 0x%08X sets TMRx.pri; the user-mode "
                              "write gate is not modelled", Index(ch), value);
    }
    const bool was_running = Running(ch);
    const bool run         = (value & kModeEnable) != 0u;
    const bool in_transfer = was_running && InReloadWindow(ch, cycle);
    if (in_transfer && (!run || (value & kModeReload) == 0u)) {
        emu_.Get<Fatal>().Die("IOP13xx TMR%u write 0x%08X clears enable or reload during the "
                              "TRRx-to-TCRx transfer (TMR 0x%08X)", Index(ch), value, ch.mode);
    }
    if (was_running && run && ch.stuck_zero && (value & kModeReload) == 0u) {
        emu_.Get<Fatal>().Die("IOP13xx TMR%u write 0x%08X clears TMRx.reload while TCRx "
                              "holds 0 with TRRx 0", Index(ch), value);
    }
    /* Figure 117 (printed p. 812): from TC Detected State with reload set the
       timer loads TCRx = TRRx. */
    const uint32_t count = in_transfer   ? ch.reload
                         : was_running   ? CountAt(ch, cycle)
                                         : ch.stopped_count;
    ch.mode = value & ~kModeTc;
    if (!run) {
        ch.stopped_count = count;
        ch.stuck_zero    = false;
        ch.has_last      = false;
    } else {
        /* Table 493 (printed p. 810): a store to TMRx.csel re-synchronizes the
           clock cycle that decrements TCRx. */
        if (!SetTickRatio(ch)) RatioOverflow(ch);
        ch.counter.Anchor(cycle, 0u);
        if (!was_running || in_transfer) {
            Load(ch, 0u, count);
        } else if (!ch.stuck_zero) {
            ch.has_last      = false;
            ch.next_terminal = count;
        }
    }
    Arm(ch);
}

/* Table 493 (printed p. 810): the value written to TCRx becomes the active
   count, and a running timer decrements it in the current clock cycle. */
void Iop13xxTimers::WriteCount(Channel& ch, uint32_t value, uint64_t cycle) {
    if (Advance(ch, cycle)) Arm(ch);
    if (!Running(ch)) {
        ch.stopped_count = value;
        return;
    }
    Load(ch, ch.counter.TicksSince(cycle), value);
    Arm(ch);
}

/* Table 493 (printed p. 810): a TRRx write during the TRRx-to-TCRx transfer is
   also transferred into TCRx. */
void Iop13xxTimers::WriteReload(Channel& ch, uint32_t value, uint64_t cycle) {
    if (Advance(ch, cycle)) Arm(ch);
    if (Running(ch) && ch.stuck_zero && value != 0u) {
        emu_.Get<Fatal>().Die("IOP13xx TRR%u write 0x%08X while an auto-reload timer "
                              "holds TCRx 0 with TRRx 0", Index(ch), value);
    }
    ch.reload = value;
    if (!Running(ch) || ch.stuck_zero || !InReloadWindow(ch, cycle)) return;
    if (value == 0u) {
        emu_.Get<Fatal>().Die("IOP13xx TRR%u write 0 during the TRRx-to-TCRx transfer",
                              Index(ch));
    }
    ch.next_terminal = ch.last_terminal + ReloadDelay(ch.mode) + value;
    Arm(ch);
}

void Iop13xxTimers::AdvanceAll(uint64_t cycle) {
    for (Channel& ch : timer_) {
        if (Advance(ch, cycle)) Arm(ch);
    }
}

void Iop13xxTimers::OnChannelEvent(Channel& ch) {
    if (Advance(ch, clock_->Cycles())) Arm(ch);
    PublishLevels();
}

/* Table 495 (printed p. 813) and section 12.4.5 (printed p. 818): P_RST#
   clears TMRx, TCRx, TRRx and TISR. */
void Iop13xxTimers::ResetState() {
    for (Channel& ch : timer_) {
        ch.mode          = 0;
        ch.reload        = 0;
        ch.stopped_count = 0;
        ch.next_terminal = 0;
        ch.last_terminal = 0;
        ch.has_last      = false;
        ch.stuck_zero    = false;
        clock_->Disarm(ch.event);
    }
    tisr_      = 0;
    published_ = 0;
}

/* Section 12.4.5 (printed p. 818): a set TISR bit is the level-sensitive
   request to the interrupt controller. */
void Iop13xxTimers::PublishLevels() {
    const uint32_t delta = (tisr_ ^ published_) & kTisrTimers;
    if (delta == 0u) return;
    auto& irq = emu_.Get<IrqController>();
    for (unsigned i = 0; i < 2u; ++i) {
        const uint32_t bit = 1u << i;
        if ((delta & bit) == 0u) continue;
        if ((tisr_ & bit) != 0u)
            irq.AssertIrq(kSourceOfTimer[i]);
        else
            irq.DeAssertIrq(kSourceOfTimer[i]);
    }
    published_ = tisr_ & kTisrTimers;
}

uint32_t Iop13xxTimers::Read(uint32_t key) {
    const uint64_t now   = clock_->Cycles();
    uint32_t       value = 0;
    switch (key) {
    case kCp6Timer0Control: value = ReadMode(timer_[0], now); break;
    case kCp6Timer1Control: value = ReadMode(timer_[1], now); break;
    case kCp6Timer0Counter: value = CountAt(timer_[0], now); break;
    case kCp6Timer1Counter: value = CountAt(timer_[1], now); break;
    case kCp6Timer0Reload:  value = timer_[0].reload; break;
    case kCp6Timer1Reload:  value = timer_[1].reload; break;
    /* Table 500 (printed p. 818): the TISR bits are marked RC (Read Clear),
       while section 12.4.5 and each bit row clear a request by a write of 1. */
    case kCp6TimerStatus:
        emu_.Get<Fatal>().Die("IOP13xx TISR read (TISR 0x%X): whether a read clears the "
                              "pending bits is not modelled", tisr_);
    case kCp6WatchdogCtrl:  value = watchdog_->ReadControl(); break;
    case kCp6WatchdogStat:  value = watchdog_->ReadSetup(); break;
    default: emu_.Get<Fatal>().Die("IOP13xx timer unit: read of CP6 key 0x%04X", key);
    }
    PublishLevels();
    return value;
}

void Iop13xxTimers::Write(uint32_t key, uint32_t value) {
    const uint64_t now = clock_->Cycles();
    switch (key) {
    case kCp6Timer0Control: WriteMode(timer_[0], value, now); break;
    case kCp6Timer1Control: WriteMode(timer_[1], value, now); break;
    case kCp6Timer0Counter: WriteCount(timer_[0], value, now); break;
    case kCp6Timer1Counter: WriteCount(timer_[1], value, now); break;
    case kCp6Timer0Reload:  WriteReload(timer_[0], value, now); break;
    case kCp6Timer1Reload:  WriteReload(timer_[1], value, now); break;
    case kCp6TimerStatus:
        if ((value & ~kTisrMask) != 0u) {
            emu_.Get<Fatal>().Die("IOP13xx TISR write 0x%08X sets reserved bits [31:3]",
                                  value);
        }
        AdvanceAll(now);
        tisr_ &= ~value;
        for (Channel& ch : timer_) Arm(ch);
        if ((value & kTisrWatchdog) != 0u) watchdog_->ClearPending();
        break;
    case kCp6WatchdogCtrl: watchdog_->WriteControl(value); break;
    case kCp6WatchdogStat: watchdog_->WriteSetup(value); break;
    default:
        emu_.Get<Fatal>().Die("IOP13xx timer unit: write 0x%08X to CP6 key 0x%04X", value,
                              key);
    }
    PublishLevels();
}

void Iop13xxTimers::SaveChannel(StateWriter& w, Channel& ch, uint64_t cycle) {
    const ChannelNames& n     = kChannelNames[Index(ch)];
    const uint32_t      count = CountAt(ch, cycle);
    const bool          run   = Running(ch) && !ch.stuck_zero;
    const uint64_t      since = ch.counter.TicksSince(cycle) - ch.last_terminal;
    const uint64_t      age   = run && ch.has_last && since < kTerminalAgeNone
                                    ? since : kTerminalAgeNone;
    w.Write(n.mode, ch.mode);
    w.Write(n.reload, ch.reload);
    w.Write(n.count, count);
    w.Write<uint64_t>(n.terminal_age, age);
    w.Write(n.stuck_zero, ch.stuck_zero);
    w.Write<uint64_t>(n.phase, run ? ch.counter.PhaseAt(cycle) : 0u);
    w.Write<uint64_t>(n.phase_den, ch.counter.PhaseDenominator());
}

void Iop13xxTimers::RestoreChannel(StateReader& r, Channel& ch, uint64_t cycle) {
    const ChannelNames& n     = kChannelNames[Index(ch)];
    uint32_t            count = 0;
    uint64_t            age   = kTerminalAgeNone;
    uint64_t            phase = 0, phase_den = 1;
    r.Read(n.mode, ch.mode);
    r.Read(n.reload, ch.reload);
    r.Read(n.count, count);
    r.Read(n.terminal_age, age);
    r.Read(n.stuck_zero, ch.stuck_zero);
    r.Read(n.phase, phase);
    r.Read(n.phase_den, phase_den);
    const bool recent = age < kTerminalAgeNone;
    ch.has_last      = recent;
    ch.last_terminal = recent ? 0u - age : 0u;
    if (!Running(ch)) {
        ch.stopped_count = count;
        return;
    }
    if (!SetTickRatio(ch)) RatioOverflow(ch);
    ch.counter.AnchorAtPhase(cycle, 0u, phase, phase_den);
    if (!ch.stuck_zero) {
        ch.next_terminal = recent && age == 0u && ReloadDelay(ch.mode) != 0u
                               ? static_cast<uint64_t>(ch.reload) + 1u
                               : count;
    }
}

void Iop13xxTimers::SaveState(StateWriter& w) {
    const uint64_t now = clock_->Cycles();
    AdvanceAll(now);
    for (Channel& ch : timer_) SaveChannel(w, ch, now);
    w.Write("tisr_timers", tisr_);
    watchdog_->SaveState(w);
}

void Iop13xxTimers::RestoreState(StateReader& r) {
    const uint64_t now = clock_->Cycles();
    for (Channel& ch : timer_) RestoreChannel(r, ch, now);
    r.Read("tisr_timers", tisr_);
    for (Channel& ch : timer_) Arm(ch);
    watchdog_->RestoreState(r);
}

void Iop13xxTimers::PostRestore() {
    published_ = ~tisr_ & kTisrTimers;
    PublishLevels();
    watchdog_->PostRestore();
}

REGISTER_SERVICE(Iop13xxTimers);
