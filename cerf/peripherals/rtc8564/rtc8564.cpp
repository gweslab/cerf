#include "rtc8564_wiring.h"

#include "../../core/cerf_emulator.h"
#include "../../core/steady_time.h"
#include "../../socs/iop13xx/iop13xx_i2c_device.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <ctime>
#include <mutex>
#include <thread>

namespace {

constexpr uint8_t kAddressWrite = 0xA2u;
constexpr uint8_t kAddressRead = 0xA3u;
constexpr uint8_t kControl1 = 0x00u;
constexpr uint8_t kControl2 = 0x01u;
constexpr uint8_t kSeconds = 0x02u;
constexpr uint8_t kMinutes = 0x03u;
constexpr uint8_t kHours = 0x04u;
constexpr uint8_t kDays = 0x05u;
constexpr uint8_t kWeekdays = 0x06u;
constexpr uint8_t kMonths = 0x07u;
constexpr uint8_t kYears = 0x08u;
constexpr uint8_t kTimerControl = 0x0Eu;
constexpr uint8_t kTimer = 0x0Fu;
constexpr uint8_t kStop = 0x20u;
constexpr uint8_t kTie = 0x01u;
constexpr uint8_t kAie = 0x02u;
constexpr uint8_t kTf = 0x04u;
constexpr uint8_t kAf = 0x08u;
constexpr uint8_t kTiTp = 0x10u;
constexpr uint8_t kControl2Writable = kTie | kAie | kTf | kAf | kTiTp;
constexpr uint8_t kTimerEnable = 0x80u;
constexpr uint8_t kTimerFrequencyMask = 0x03u;

std::tm LocalTime(std::time_t value) {
    std::tm result{};
#if defined(_WIN32)
    localtime_s(&result, &value);
#else
    localtime_r(&value, &result);
#endif
    return result;
}

uint8_t BinToBcd(int value) {
    return static_cast<uint8_t>(((value / 10) << 4) | (value % 10));
}

bool BcdToBin(uint8_t value, int maximum, int& result) {
    const int high = (value >> 4) & 0x0F;
    const int low = value & 0x0F;
    if (high > 9 || low > 9) return false;
    result = high * 10 + low;
    return result <= maximum;
}

class Rtc8564 final : public Iop13xxI2cDevice {
public:
    using Iop13xxI2cDevice::Iop13xxI2cDevice;

    bool ShouldRegister() override { return emu_.TryGet<Rtc8564Wiring>() != nullptr; }

    void OnReady() override {
        MaterializeClockRegisters();
        registers_[kControl2] = kTie | kTiTp;
        registers_[0x09] = 0x80u;
        registers_[0x0A] = 0x80u;
        registers_[0x0B] = 0x80u;
        registers_[0x0C] = 0x80u;
        registers_[0x0D] = 0;
        registers_[kTimerControl] = kTimerEnable | 0x02u;
        registers_[kTimer] = 0x01u;
        RestartTimer();
        timer_thread_ = std::thread(&Rtc8564::TimerLoop, this);
    }

    void OnShutdown() override {
        timer_stop_.store(true, std::memory_order_release);
        if (timer_thread_.joinable()) timer_thread_.join();
        std::lock_guard<std::mutex> guard(mutex_);
        SetInterrupt(false);
    }

    bool Address(uint8_t address_byte) override {
        std::lock_guard<std::mutex> guard(mutex_);
        if (address_byte == kAddressWrite) {
            phase_ = 1;
            read_mode_ = false;
        } else if (address_byte == kAddressRead) {
            phase_ = 3;
            read_mode_ = true;
        } else {
            phase_ = 0;
            read_mode_ = false;
            return false;
        }
        UpdateInterrupt(HostSteadyMicros());
        return true;
    }

    bool WriteByte(uint8_t value) override {
        std::lock_guard<std::mutex> guard(mutex_);
        if (phase_ == 1) {
            pointer_ = value & 0x0Fu;
            phase_ = 2;
            return true;
        }
        if (phase_ != 2 || read_mode_) return false;
        WriteRegister(pointer_, value);
        IncrementPointer();
        UpdateInterrupt(HostSteadyMicros());
        return true;
    }

    bool ReadByte(uint8_t& value) override {
        std::lock_guard<std::mutex> guard(mutex_);
        if (phase_ != 3 || !read_mode_) {
            value = 0xFFu;
            return false;
        }
        value = ReadRegister(pointer_);
        IncrementPointer();
        UpdateInterrupt(HostSteadyMicros());
        return true;
    }

    void Stop() override {
        std::lock_guard<std::mutex> guard(mutex_);
        phase_ = 0;
        read_mode_ = false;
    }

    void SaveState(StateWriter& writer) override {
        std::lock_guard<std::mutex> guard(mutex_);
        const uint64_t now = HostSteadyMicros();
        MaterializeTimer();
        if (!Stopped()) {
            MaterializeClockRegisters();
            MaterializeAlarm();
        }
        const uint64_t timer_elapsed_us = TimerElapsedMicros(now);
        const uint64_t pulse_remaining_us = interrupt_pulse_until_ > now ? interrupt_pulse_until_ - now : 0;
        writer.Write("pointer", pointer_);
        writer.Write("phase", phase_);
        writer.Write("read_mode", read_mode_);
        writer.Write("epoch_delta_seconds", epoch_delta_seconds_);
        writer.Write("timer_elapsed_us", timer_elapsed_us);
        writer.Write("timer_reload", timer_reload_);
        writer.Write("interrupt_asserted", interrupt_asserted_);
        writer.Write("pulse_remaining_us", pulse_remaining_us);
        writer.WriteBytes("registers", registers_.data(), registers_.size());
    }

    void RestoreState(StateReader& reader) override {
        std::lock_guard<std::mutex> guard(mutex_);
        reader.Read("pointer", pointer_);
        reader.Read("phase", phase_);
        reader.Read("read_mode", read_mode_);
        reader.Read("epoch_delta_seconds", epoch_delta_seconds_);
        uint64_t timer_elapsed_us = 0;
        reader.Read("timer_elapsed_us", timer_elapsed_us);
        reader.Read("timer_reload", timer_reload_);
        reader.Read("interrupt_asserted", interrupt_asserted_);
        uint64_t pulse_remaining_us = 0;
        reader.Read("pulse_remaining_us", pulse_remaining_us);
        reader.ReadBytes("registers", registers_.data(), registers_.size());
        pointer_ &= 0x0Fu;
        phase_ = phase_ <= 3 ? phase_ : 0;
        const uint64_t now = HostSteadyMicros();
        interrupt_pulse_until_ = pulse_remaining_us != 0 ? now + pulse_remaining_us : 0;
        if (!TimerEnabled()) {
            timer_epoch_us_ = 0;
            timer_reload_ = 0;
        } else {
            const uint64_t interval = TimerIntervalMicros();
            if (interval != 0) {
                timer_elapsed_us %= interval;
                timer_epoch_us_ = now - timer_elapsed_us;
            } else {
                RestartTimer();
            }
        }
        alarm_match_latched_ = AlarmMatchesNow();
    }

    void PostRestore() override {
        std::lock_guard<std::mutex> guard(mutex_);
        const bool restored_asserted = interrupt_asserted_;
        interrupt_asserted_ = !restored_asserted;
        SetInterrupt(restored_asserted);
        UpdateInterrupt(HostSteadyMicros());
    }

private:
    bool Stopped() const { return (registers_[kControl1] & kStop) != 0; }

    void IncrementPointer() { pointer_ = static_cast<uint8_t>((pointer_ + 1u) & 0x0Fu); }

    uint8_t ReadRegister(uint8_t index) {
        index &= 0x0Fu;
        MaterializeTimer();
        if (!Stopped()) {
            MaterializeClockRegisters();
            MaterializeAlarm();
        }
        return registers_[index];
    }

    void WriteRegister(uint8_t index, uint8_t value) {
        index &= 0x0Fu;
        if (index == kControl1) {
            const bool was_stopped = Stopped();
            if (!was_stopped && (value & kStop)) MaterializeClockRegisters();
            registers_[index] = value & kStop;
            if (was_stopped && !Stopped()) CommitClockRegisters();
            return;
        }

        switch (index) {
        case kControl2:
            MaterializeTimer();
            WriteControl2(value);
            break;
        case 0x02: registers_[index] = value & 0x7Fu; break;
        case 0x03: registers_[index] = value & 0x7Fu; break;
        case 0x04: registers_[index] = value & 0x3Fu; break;
        case 0x05: registers_[index] = value & 0x3Fu; break;
        case 0x06: registers_[index] = value & 0x07u; break;
        case 0x07: registers_[index] = value & 0x9Fu; break;
        case 0x08: registers_[index] = value; break;
        case 0x09: registers_[index] = value; break;
        case 0x0A: registers_[index] = value & 0xBFu; break;
        case 0x0B: registers_[index] = value & 0xBFu; break;
        case 0x0C: registers_[index] = value & 0x87u; break;
        case 0x0D: registers_[index] = value & 0x83u; break;
        case kTimerControl:
            MaterializeTimer();
            registers_[index] = value & (kTimerEnable | kTimerFrequencyMask);
            ResetTimerState();
            break;
        case kTimer:
            MaterializeTimer();
            registers_[index] = value;
            ResetTimerState();
            break;
        }

        if (!Stopped() && index >= kSeconds && index <= kYears) CommitClockRegisters();
        if (!Stopped()) {
            MaterializeClockRegisters();
            if (index >= 0x09u && index <= 0x0Cu) alarm_match_latched_ = AlarmMatchesNow();
            MaterializeAlarm();
        }
    }

    void ResetTimerState() {
        if (TimerEnabled())
            RestartTimer();
        else {
            timer_epoch_us_ = 0;
            timer_reload_ = 0;
        }
    }

    bool TimerEnabled() const { return (registers_[kTimerControl] & kTimerEnable) != 0 && registers_[kTimer] != 0; }

    uint64_t TimerTickMicros() const {
        /* NXP PCF8564A Rev. 3, section 8.8.1, Table 24. */
        switch (registers_[kTimerControl] & kTimerFrequencyMask) {
        case 0: return 244u;
        case 1: return 15625u;
        case 2: return 1000000u;
        case 3: return 60000000u;
        default: return 1000000u;
        }
    }

    uint64_t TimerIntervalMicros() const {
        if (!TimerEnabled() || timer_reload_ == 0) return 0;
        return static_cast<uint64_t>(timer_reload_) * TimerTickMicros();
    }

    uint64_t TimerElapsedMicros(uint64_t now) const {
        const uint64_t interval = TimerIntervalMicros();
        if (interval == 0 || timer_epoch_us_ == 0) return 0;
        const uint64_t elapsed = now >= timer_epoch_us_ ? now - timer_epoch_us_ : 0;
        return elapsed % interval;
    }

    void RestartTimer() {
        timer_reload_ = registers_[kTimer];
        timer_epoch_us_ = HostSteadyMicros();
    }

    bool MaterializeTimer() {
        if (!TimerEnabled()) {
            timer_epoch_us_ = 0;
            timer_reload_ = 0;
            return false;
        }
        if (timer_epoch_us_ == 0 || timer_reload_ == 0) {
            RestartTimer();
            return false;
        }
        const uint64_t interval = TimerIntervalMicros();
        const uint64_t now = HostSteadyMicros();
        const uint64_t elapsed = now - timer_epoch_us_;
        if (interval == 0) return false;
        const bool expired = elapsed >= interval;
        if (expired) {
            registers_[kControl2] |= kTf;
            timer_epoch_us_ += (elapsed / interval) * interval;
        }
        const uint64_t elapsed_ticks = (now - timer_epoch_us_) / TimerTickMicros();
        registers_[kTimer] = static_cast<uint8_t>(timer_reload_ - elapsed_ticks);
        return expired;
    }

    bool AlarmFieldEnabled(uint8_t alarm_index) const { return (registers_[alarm_index] & 0x80u) == 0u; }

    bool AlarmMatches(uint8_t alarm_index, uint8_t clock_index, uint8_t mask) const {
        const uint8_t alarm = registers_[alarm_index];
        if (!AlarmFieldEnabled(alarm_index)) return true;
        return (alarm & mask) == (registers_[clock_index] & mask);
    }

    bool AlarmMatchesNow() const {
        /* NXP PCF8564A Rev. 3, section 8.6.5: AF is set when every enabled
           alarm register comparison matches the current time. */
        const bool any_enabled = AlarmFieldEnabled(0x09u) || AlarmFieldEnabled(0x0Au) || AlarmFieldEnabled(0x0Bu) ||
                                 AlarmFieldEnabled(0x0Cu);
        return any_enabled && AlarmMatches(0x09u, kMinutes, 0x7Fu) && AlarmMatches(0x0Au, kHours, 0x3Fu) &&
               AlarmMatches(0x0Bu, kDays, 0x3Fu) && AlarmMatches(0x0Cu, kWeekdays, 0x07u);
    }

    void MaterializeAlarm() {
        const bool matches = AlarmMatchesNow();
        if (matches && !alarm_match_latched_) registers_[kControl2] |= kAf;
        alarm_match_latched_ = matches;
    }

    bool TimerInterruptEnabled() const { return (registers_[kControl2] & kTie) != 0; }

    bool RepeatedTimerMode() const { return (registers_[kControl2] & kTiTp) != 0; }

    bool LevelInterruptActive() const {
        const bool alarm = (registers_[kControl2] & (kAf | kAie)) == (kAf | kAie);
        const bool timer = !RepeatedTimerMode() && (registers_[kControl2] & (kTf | kTie)) == (kTf | kTie);
        return alarm || timer;
    }

    uint64_t PulseRecoveryMicros() const {
        if (!RepeatedTimerMode()) return 0;
        const bool count_is_one = registers_[kTimer] == 1;
        switch (registers_[kTimerControl] & kTimerFrequencyMask) {
        case 0: return count_is_one ? 122u : 244u;
        case 1: return count_is_one ? 7813u : 15625u;
        default: return 15625u;
        }
    }

    void WriteControl2(uint8_t value) {
        /* NXP PCF8564A Rev. 3, section 8.3.2.1: AF/TF clear on writing zero. */
        const uint8_t flags = registers_[kControl2] & (kTf | kAf);
        const uint8_t requested = value & kControl2Writable;
        uint8_t next = requested & ~(kTf | kAf);
        if ((requested & kTf) && (flags & kTf)) next |= kTf;
        if ((requested & kAf) && (flags & kAf)) next |= kAf;
        registers_[kControl2] = next;
    }

    void MaterializeClockRegisters() {
        const std::time_t now = std::time(nullptr) + static_cast<std::time_t>(epoch_delta_seconds_);
        const std::tm local = LocalTime(now);
        const int base = emu_.Get<Rtc8564Wiring>().CalendarYearBase();
        int year = local.tm_year + 1900 - base;
        if (year < 0) year = 0;
        if (year > 99) year = 99;
        registers_[kSeconds] = BinToBcd(local.tm_sec);
        registers_[kMinutes] = BinToBcd(local.tm_min);
        registers_[kHours] = BinToBcd(local.tm_hour);
        registers_[kDays] = BinToBcd(local.tm_mday);
        registers_[kWeekdays] = static_cast<uint8_t>(local.tm_wday & 0x07);
        registers_[kMonths] = BinToBcd(local.tm_mon + 1);
        registers_[kYears] = BinToBcd(year);
    }

    void CommitClockRegisters() {
        int second = 0, minute = 0, hour = 0, day = 0, month = 0, year = 0;
        if (!BcdToBin(registers_[kSeconds] & 0x7Fu, 59, second) ||
            !BcdToBin(registers_[kMinutes] & 0x7Fu, 59, minute) || !BcdToBin(registers_[kHours] & 0x3Fu, 23, hour) ||
            !BcdToBin(registers_[kDays] & 0x3Fu, 31, day) || day < 1 ||
            !BcdToBin(registers_[kMonths] & 0x1Fu, 12, month) || month < 1 || !BcdToBin(registers_[kYears], 99, year)) {
            return;
        }
        std::tm target{};
        target.tm_sec = second;
        target.tm_min = minute;
        target.tm_hour = hour;
        target.tm_mday = day;
        target.tm_mon = month - 1;
        target.tm_year = emu_.Get<Rtc8564Wiring>().CalendarYearBase() + year - 1900;
        target.tm_isdst = -1;
        const std::time_t timestamp = std::mktime(&target);
        if (timestamp != static_cast<std::time_t>(-1))
            epoch_delta_seconds_ = static_cast<int64_t>(timestamp - std::time(nullptr));
    }

    void TimerLoop() {
        auto& freeze = emu_.Get<EmulationFreeze>();
        while (!timer_stop_.load(std::memory_order_acquire)) {
            {
                auto frozen = freeze.WorkerSection();
                std::lock_guard<std::mutex> guard(mutex_);
                const bool event = MaterializeTimer();
                if (!Stopped()) {
                    MaterializeClockRegisters();
                    MaterializeAlarm();
                }
                if (event && TimerInterruptEnabled() && RepeatedTimerMode()) {
                    interrupt_pulse_until_ = HostSteadyMicros() + PulseRecoveryMicros();
                }
                UpdateInterrupt(HostSteadyMicros());
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    void UpdateInterrupt(uint64_t now) {
        if (interrupt_pulse_until_ != 0 && now >= interrupt_pulse_until_) interrupt_pulse_until_ = 0;
        /* NXP PCF8564A Rev. 3, section 8.3.2.1: INT is the logical OR of
           enabled timer and alarm conditions; I2C bus activity is not an input. */
        SetInterrupt(interrupt_pulse_until_ != 0 || LevelInterruptActive());
    }

    void SetInterrupt(bool active) {
        if (active == interrupt_asserted_) return;
        interrupt_asserted_ = active;
        emu_.Get<Rtc8564Wiring>().SetInterrupt(active);
    }

    std::array<uint8_t, 16> registers_{};
    uint8_t pointer_ = 0;
    uint32_t phase_ = 0;
    bool read_mode_ = false;
    int64_t epoch_delta_seconds_ = 0;
    uint64_t timer_epoch_us_ = 0;
    uint8_t timer_reload_ = 0;
    std::mutex mutex_;
    std::thread timer_thread_;
    std::atomic<bool> timer_stop_{false};
    bool interrupt_asserted_ = false;
    uint64_t interrupt_pulse_until_ = 0;
    bool alarm_match_latched_ = false;
};

REGISTER_SERVICE_AS(Rtc8564, Iop13xxI2cDevice);

} // namespace
