#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../socs/raster_scan_clock.h"
#include "../../state/state_stream.h"
#include "odo_arm720_board_intc.h"
#include "odo_id.h"

#include <cstdint>

namespace {

constexpr uint32_t kCpuTimerPaBase = 0x10000400u;
constexpr uint32_t kCpuTimerSize   = 0x0Cu;

constexpr uint32_t kSlotCpuisr = 0;
constexpr uint32_t kSlotTir    = 1;
constexpr uint32_t kSlotCount  = 3;

constexpr uint32_t kTimerModeMask = 0x00000C00u;
constexpr uint32_t kTimerModeOff  = 0x00000000u;
constexpr uint32_t kTimerMode25ms = 0x00000800u;
constexpr uint32_t kTimerMode1ms  = 0x00000C00u;
constexpr uint32_t kTirSetBit     = 0x00000001u;
constexpr uint32_t kStartupSetBit = 0x00000008u;
constexpr uint32_t kCpuisrStored  = kTimerModeMask | kStartupSetBit;

constexpr GuestCycleClock::Rate kCounterRate{3686400u, 1u};
constexpr uint32_t kCounts25ms = 92160u;
constexpr uint32_t kCounts1ms  = 3686u;

class OdoArm720CpuTimer : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetBoardId() == BoardId::Odo;
    }

    void OnReady() override {
        clock_ = &emu_.Get<GuestCycleClock>();
        intc_  = &static_cast<OdoArm720BoardIntc&>(emu_.Get<IrqController>());
        event_ = clock_->Add([this] { OnPeriodEnd(); });
        clock_->RegisterRateListener([this] { OnRateChange(); });
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) { ResetLine(); });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kCpuTimerPaBase; }
    uint32_t MmioSize() const override { return kCpuTimerSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t slot = (addr - MmioBase()) / 4u;
        if (slot >= kSlotCount) HaltUnsupportedAccess("ReadWord", addr, 0);
        return ReadSlot(slot);
    }

    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t off  = addr - MmioBase();
        const uint32_t slot = (off & ~0x2u) / 4u;
        if (slot >= kSlotCount) HaltUnsupportedAccess("ReadHalf", addr, 0);
        const uint32_t value = ReadSlot(slot);
        return (off & 0x2u) ? static_cast<uint16_t>(value >> 16)
                            : static_cast<uint16_t>(value & 0xFFFFu);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t slot = (addr - MmioBase()) / 4u;
        if (slot == kSlotCpuisr) {
            WriteCpuisr(value);
        } else if (slot == kSlotTir) {
            WriteTir(value);
        } else {
            HaltUnsupportedAccess("WriteWord", addr, value);
        }
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        emu_.Get<Fatal>().Die(
            "odo cpu timer: 16-bit write 0x%04X at 0x%08X; the half-width write "
            "of these registers is not modelled", value, addr);
    }

    void SaveState(StateWriter& w) override {
        const uint64_t now     = clock_->Cycles();
        const bool     running = Running();
        const RasterScanClock::Position at =
            running ? scan_.PositionAt(now) : RasterScanClock::Position{};
        w.Write<uint32_t>("cpuisr", cpuisr_);
        w.Write<uint32_t>("tir", tir_);
        w.Write<uint32_t>("tvr", running ? Tvr(now) : 0u);
        w.Write<uint64_t>("grid_phase", at.phase);
        w.Write<uint64_t>("grid_phase_den", at.phase_den);
    }

    void RestoreState(StateReader& r) override {
        const uint64_t now = clock_->Cycles();
        uint32_t cpuisr = 0, tir = 0, tvr = 0;
        uint64_t phase = 0, phase_den = 0;
        r.Read("cpuisr", cpuisr);
        r.Read("tir", tir);
        r.Read("tvr", tvr);
        r.Read("grid_phase", phase);
        r.Read("grid_phase_den", phase_den);
        const uint32_t mode = cpuisr & kTimerModeMask;
        if (mode == kTimerModeOff) {
            cpuisr_ = cpuisr;
            tir_    = tir;
            clock_->Disarm(event_);
            return;
        }
        const uint32_t counts = CountsFor(mode);
        RequireGrid(scan_.Resume(now, clock_->ClockRate(), kCounterRate, PeriodFrame(counts),
                                 RasterScanClock::Position{counts - 1u - tvr, phase, phase_den}),
                    "the restored period grid");
        cpuisr_ = cpuisr;
        tir_    = tir;
        ArmNextPeriodEnd(now);
    }

    void PostRestore() override {
        intc_->SetTimerIrqLevel((tir_ & kTirSetBit) != 0u);
    }

private:
    void ResetLine() {
        cpuisr_ = 0u;
        tir_    = 0u;
        clock_->Disarm(event_);
        intc_->SetTimerIrqLevel(false);
    }

    bool Running() const { return (cpuisr_ & kTimerModeMask) != kTimerModeOff; }

    static uint32_t CountsFor(uint32_t mode) {
        return mode == kTimerMode25ms ? kCounts25ms : kCounts1ms;
    }

    static RasterScanClock::Frame PeriodFrame(uint32_t counts) {
        RasterScanClock::Frame frame;
        frame.ticks   = counts;
        frame.edge[0] = counts;
        frame.edges   = 1u;
        return frame;
    }

    uint32_t Counts() const { return CountsFor(cpuisr_ & kTimerModeMask); }

    uint32_t Tvr(uint64_t now) const {
        return Counts() - 1u - static_cast<uint32_t>(scan_.TickInFrame(now));
    }

    void RequireGrid(bool placed, const char* what) {
        if (placed) return;
        const GuestCycleClock::Rate core = clock_->ClockRate();
        emu_.Get<Fatal>().Die(
            "odo cpu timer: %s does not fit the 64-bit scale of the %llu Hz counter "
            "against the %llu/%llu Hz core", what,
            static_cast<unsigned long long>(kCounterRate.num),
            static_cast<unsigned long long>(core.num),
            static_cast<unsigned long long>(core.den));
    }

    uint32_t ReadSlot(uint32_t slot) {
        if (slot == kSlotCpuisr) return cpuisr_;
        if (slot == kSlotTir)    return tir_;
        if (!Running()) {
            emu_.Get<Fatal>().Die(
                "odo cpu timer: TVR read with the period mode off (CPUISR "
                "0x%08X); the counter outside a period mode is not modelled",
                cpuisr_);
        }
        return Tvr(clock_->Cycles());
    }

    void WriteCpuisr(uint32_t value) {
        if ((value & ~kCpuisrStored) != 0u) {
            emu_.Get<Fatal>().Die(
                "odo cpu timer: CPUISR write 0x%08X sets bits outside the period "
                "mode field and bit 3; those bits are not modelled", value);
        }
        const uint32_t old_mode = cpuisr_ & kTimerModeMask;
        const uint32_t new_mode = value & kTimerModeMask;
        if (new_mode != old_mode) {
            if (old_mode != kTimerModeOff) {
                emu_.Get<Fatal>().Die(
                    "odo cpu timer: CPUISR write 0x%08X changes the running period "
                    "mode 0x%03X to 0x%03X; the countdown across that change is not "
                    "modelled", value, old_mode, new_mode);
            }
            if (new_mode != kTimerMode25ms && new_mode != kTimerMode1ms) {
                emu_.Get<Fatal>().Die(
                    "odo cpu timer: CPUISR write 0x%08X selects period mode 0x%03X, "
                    "whose period is not modelled", value, new_mode);
            }
        }
        LOG(SocTimer, "odo cpu timer: CPUISR 0x%08X -> 0x%08X\n", cpuisr_, value);
        cpuisr_ = value;
        if (new_mode == old_mode) return;
        const uint64_t now = clock_->Cycles();
        RequireGrid(scan_.Start(now, clock_->ClockRate(), kCounterRate, PeriodFrame(Counts())),
                    "the period grid");
        ArmNextPeriodEnd(now);
    }

    void WriteTir(uint32_t value) {
        if ((value & ~kTirSetBit) != 0u) {
            emu_.Get<Fatal>().Die(
                "odo cpu timer: TIR write 0x%08X sets a bit other than the "
                "period-end bit", value);
        }
        tir_ &= ~value;
        intc_->SetTimerIrqLevel((tir_ & kTirSetBit) != 0u);
        if (Running() && (value & kTirSetBit) != 0u) ArmNextPeriodEnd(clock_->Cycles());
    }

    void ArmNextPeriodEnd(uint64_t now) {
        if ((tir_ & kTirSetBit) != 0u) {
            clock_->Disarm(event_);
            return;
        }
        uint64_t at = 0;
        RequireGrid(scan_.EdgeCycle(scan_.EdgesThrough(now), at), "the next period end");
        clock_->Arm(event_, at);
    }

    void OnPeriodEnd() {
        tir_ |= kTirSetBit;
        intc_->SetTimerIrqLevel(true);
        ArmNextPeriodEnd(clock_->Cycles());
    }

    void OnRateChange() {
        if (!Running()) return;
        const uint64_t now = clock_->Cycles();
        RequireGrid(scan_.Rescale(now, clock_->ClockRate(), kCounterRate),
                    "the period grid at the new core rate");
        ArmNextPeriodEnd(now);
    }

    GuestCycleClock*        clock_  = nullptr;
    OdoArm720BoardIntc*     intc_   = nullptr;
    GuestCycleClock::Event* event_  = nullptr;
    RasterScanClock         scan_;
    uint32_t                cpuisr_ = 0;
    uint32_t                tir_    = 0;
};

}

REGISTER_SERVICE(OdoArm720CpuTimer);
