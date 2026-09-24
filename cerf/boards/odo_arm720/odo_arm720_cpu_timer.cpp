#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "odo_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"
#include "odo_arm720_board_intc.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <thread>

namespace {


constexpr uint32_t kCpuTimerPaBase   = 0x10000400u;
constexpr uint32_t kCpuTimerSize     = 0x0Cu;        /* 3 dwords */

constexpr uint32_t kSlotCpuisr       = 0;
constexpr uint32_t kSlotTir          = 1;
constexpr uint32_t kSlotTvr          = 2;
constexpr uint32_t kSlotCount        = 3;

constexpr uint32_t kTimerModeMask    = 0x00000C00u;  /* bits 11:10 */
constexpr uint32_t kTimerMode10ms    = 0x00000400u;
constexpr uint32_t kTimerMode25ms    = 0x00000800u;
constexpr uint32_t kTimerMode1ms     = 0x00000C00u;
constexpr uint32_t kTirSetBit        = 0x00000001u;

constexpr uint64_t kOemClockHz       = 3686400ull;

class OdoArm720CpuTimer : public Peripheral {
public:
    using Peripheral::Peripheral;

    ~OdoArm720CpuTimer() override { StopTickThread(); }

    void OnShutdown() override { StopTickThread(); }

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Odo;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        period_start_  = Clock::now();
        tick_thread_   = std::thread(&OdoArm720CpuTimer::TickLoop, this);
    }

    uint32_t MmioBase() const override { return kCpuTimerPaBase; }
    uint32_t MmioSize() const override { return kCpuTimerSize; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    uint16_t ReadHalf (uint32_t addr) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;

    void SaveState(StateWriter& w) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        w.Write("cpuisr", cpuisr_);  w.Write("tir", tir_);
    }
    void RestoreState(StateReader& r) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        r.Read("cpuisr", cpuisr_);  r.Read("tir", tir_);
        period_start_ = Clock::now();
    }
    void PostRestore() override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        static_cast<OdoArm720BoardIntc&>(emu_.Get<IrqController>())
            .SetTimerIrqLevel((tir_ & kTirSetBit) != 0);
    }

private:
    using Clock = std::chrono::steady_clock;

    uint32_t PeriodMsLocked() const;
    uint32_t TicksPerPeriodLocked() const;
    uint32_t ComputeTvrLocked(Clock::time_point now) const;
    void     TickLoop();
    void     StopTickThread() {
        stop_thread_.store(true, std::memory_order_release);
        if (tick_thread_.joinable()) tick_thread_.join();
    }

    mutable std::mutex   state_mutex_;
    uint32_t             cpuisr_     = 0;
    uint32_t             tir_        = 0;
    Clock::time_point    period_start_ = {};

    std::thread          tick_thread_;
    std::atomic<bool>    stop_thread_{false};
};

uint32_t OdoArm720CpuTimer::PeriodMsLocked() const {
    const uint32_t mode = cpuisr_ & kTimerModeMask;
    if      (mode == kTimerMode1ms)  return 1;
    else if (mode == kTimerMode10ms) return 10;
    else if (mode == kTimerMode25ms) return 25;
    return 0;
}

uint32_t OdoArm720CpuTimer::TicksPerPeriodLocked() const {
    return static_cast<uint32_t>(kOemClockHz * PeriodMsLocked() / 1000ull);
}

uint32_t OdoArm720CpuTimer::ComputeTvrLocked(Clock::time_point now) const {
    const uint32_t ticks_per_period = TicksPerPeriodLocked();
    if (ticks_per_period == 0) return 0;  /* timer off */

    const auto period_duration = std::chrono::milliseconds(PeriodMsLocked());
    const auto period_ns       = std::chrono::duration_cast<std::chrono::nanoseconds>(period_duration).count();
    const auto elapsed_ns      = std::chrono::duration_cast<std::chrono::nanoseconds>(now - period_start_).count();

    if (elapsed_ns < 0)              return ticks_per_period;
    if (elapsed_ns >= period_ns)     return 0;

    const uint64_t elapsed_ticks =
        static_cast<uint64_t>(elapsed_ns) * ticks_per_period / static_cast<uint64_t>(period_ns);
    if (elapsed_ticks >= ticks_per_period) return 0;
    return ticks_per_period - static_cast<uint32_t>(elapsed_ticks);
}

uint32_t OdoArm720CpuTimer::ReadWord(uint32_t addr) {
    const uint32_t off  = addr - MmioBase();
    const uint32_t slot = off / 4u;
    if (slot >= kSlotCount) {
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    uint32_t value = 0;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if      (slot == kSlotCpuisr) value = cpuisr_;
        else if (slot == kSlotTir)    value = tir_;
        else                          value = ComputeTvrLocked(Clock::now());
    }

#if CERF_DEV_MODE
    LOG(SocTimer, "ARM720 CPU-iface read  +0x%02X -> 0x%08X\n", off, value);
#endif
    return value;
}

void OdoArm720CpuTimer::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off  = addr - MmioBase();
    const uint32_t slot = off / 4u;
    if (slot >= kSlotCount) {
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

#if CERF_DEV_MODE
    LOG(SocTimer, "ARM720 CPU-iface write +0x%02X = 0x%08X\n", off, value);
#endif

    std::lock_guard<std::mutex> lk(state_mutex_);
    if (slot == kSlotCpuisr) {
        const uint32_t old_mode = cpuisr_ & kTimerModeMask;
        const uint32_t new_mode = value  & kTimerModeMask;
        cpuisr_ = value;
        if (old_mode != new_mode) {
            period_start_ = Clock::now();
        }
    } else if (slot == kSlotTir) {
        tir_ &= ~value;
        static_cast<OdoArm720BoardIntc&>(emu_.Get<IrqController>())
            .SetTimerIrqLevel((tir_ & kTirSetBit) != 0);
    } else {
        HaltUnsupportedAccess("WriteWord TVR", addr, value);
    }
}

void OdoArm720CpuTimer::TickLoop() {
    using namespace std::chrono;
    auto& freeze = emu_.Get<EmulationFreeze>();

    while (!stop_thread_.load(std::memory_order_acquire)) {
        uint32_t          period_ms = 0;
        Clock::time_point fire_at;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            period_ms = PeriodMsLocked();
            fire_at   = period_start_ + milliseconds(period_ms);
        }

        if (period_ms == 0) {
            /* Timer off - sleep short and re-check the mode
               register. Host doesn't expose a wake-on-write
               channel into the peripheral state, so polling at
               1 ms is the simplest correct shape. */
            std::this_thread::sleep_for(milliseconds(1));
            std::lock_guard<std::mutex> lk(state_mutex_);
            period_start_ = Clock::now();
            continue;
        }

        std::this_thread::sleep_until(fire_at);
        if (stop_thread_.load(std::memory_order_acquire)) break;

        {
            auto frozen = freeze.WorkerSection();
            std::lock_guard<std::mutex> lk(state_mutex_);
            if (PeriodMsLocked() != period_ms) continue;

            period_start_ += milliseconds(period_ms);
            tir_ |= kTirSetBit;
            static_cast<OdoArm720BoardIntc&>(emu_.Get<IrqController>())
                .SetTimerIrqLevel(true);
        }
    }
}

uint16_t OdoArm720CpuTimer::ReadHalf(uint32_t addr) {
    const uint32_t off       = addr - MmioBase();
    const uint32_t slot_off  = off & ~0x2u;          /* round to 4-byte slot */
    const uint32_t slot      = slot_off / 4u;
    if (slot >= kSlotCount) {
        HaltUnsupportedAccess("ReadHalf", addr, 0);
    }
    uint32_t slot_value = 0;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if      (slot == kSlotCpuisr) slot_value = cpuisr_;
        else if (slot == kSlotTir)    slot_value = tir_;
        else                          slot_value = ComputeTvrLocked(Clock::now());
    }
    const uint16_t value =
        (off & 0x2u) ? static_cast<uint16_t>(slot_value >> 16)
                     : static_cast<uint16_t>(slot_value & 0xFFFFu);
#if CERF_DEV_MODE
    LOG(SocTimer, "ARM720 CPU-iface read16 +0x%02X -> 0x%04X\n",
        off, value);
#endif
    return value;
}

void OdoArm720CpuTimer::WriteHalf(uint32_t addr, uint16_t value) {
    LOG(Caution, "OdoArm720CpuTimer::WriteHalf at 0x%08X = 0x%04X "
            "- the ARM720 CPU-interface registers are 32-bit-only; "
            "halt rather than guess the half-write semantic.\n",
            addr, value);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

}  /* namespace */

REGISTER_SERVICE(OdoArm720CpuTimer);
