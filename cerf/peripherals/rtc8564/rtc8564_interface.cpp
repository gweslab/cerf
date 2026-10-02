#include "rtc8564_core.h"
#include "rtc8564_wiring.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../socs/cycle_anchored_counter.h"
#include "../../socs/iop13xx/iop13xx_i2c_device.h"
#include "../../state/state_stream.h"

#include <cstdint>
#include <mutex>

namespace {

constexpr uint8_t kAddressWrite = 0xA2u;
constexpr uint8_t kAddressRead  = 0xA3u;

class Rtc8564Interface final : public Iop13xxI2cDevice {
public:
    using Iop13xxI2cDevice::Iop13xxI2cDevice;

    bool ShouldRegister() override { return emu_.TryGet<Rtc8564Wiring>() != nullptr; }

    void OnReady() override {
        clock_ = &emu_.Get<GuestCycleClock>();
        core_  = &emu_.Get<Rtc8564Core>();
        clock_->RegisterRateListener([this] { OnRateChange(); });
    }

    bool Address(uint8_t address_byte) override {
        std::lock_guard<std::mutex> guard(mutex_);
        const uint64_t now = clock_->Cycles();
        if (!open_ || TimedOut(now)) Open(now);
        if (address_byte == kAddressWrite) {
            phase_     = 1;
            read_mode_ = false;
        } else if (address_byte == kAddressRead) {
            phase_     = 3;
            read_mode_ = true;
        } else {
            phase_     = 0;
            read_mode_ = false;
            return false;
        }
        core_->Update();
        return true;
    }

    /* NXP UM10204 section 3.1.6 (p. 10): SDA left HIGH in the acknowledge clock
       pulse is the Not Acknowledge. */
    bool WriteByte(uint8_t value) override {
        std::lock_guard<std::mutex> guard(mutex_);
        if (TimedOut(clock_->Cycles())) return false;
        if (phase_ == 1) {
            pointer_ = value & 0x0Fu;
            phase_   = 2;
            return true;
        }
        if (phase_ != 2 || read_mode_) return false;
        core_->WriteAt(pointer_, value);
        if (core_->StopSet()) stop_seen_ = true;
        IncrementPointer();
        return true;
    }

    bool ReadByte(uint8_t& value) override {
        std::lock_guard<std::mutex> guard(mutex_);
        if (TimedOut(clock_->Cycles())) {
            value = 0xFFu;
            return true;
        }
        if (phase_ != 3 || !read_mode_) {
            value = 0xFFu;
            return false;
        }
        value = core_->ReadAt(pointer_);
        IncrementPointer();
        return true;
    }

    void Stop() override {
        std::lock_guard<std::mutex> guard(mutex_);
        phase_     = 0;
        read_mode_ = false;
        open_      = false;
        timed_out_ = false;
    }

    void SaveState(StateWriter& writer) override {
        {
            std::lock_guard<std::mutex> guard(mutex_);
            const uint64_t now = clock_->Cycles();
            writer.Write("pointer", pointer_);
            writer.Write("phase", phase_);
            writer.Write("read_mode", read_mode_);
            writer.Write("bus_open", open_);
            writer.Write("bus_timed_out", timed_out_);
            writer.Write("bus_stop_seen", stop_seen_);
            writer.Write<uint32_t>("bus_seconds", open_ ? window_.CountAt(now) : 0u);
            writer.Write<uint64_t>("bus_phase", open_ ? window_.PhaseAt(now) : 0u);
            writer.Write<uint64_t>("bus_phase_den", window_.PhaseDenominator());
        }
        core_->SaveState(writer);
    }

    void RestoreState(StateReader& reader) override {
        {
            std::lock_guard<std::mutex> guard(mutex_);
            uint32_t seconds = 0;
            uint64_t phase = 0, den = 1;
            reader.Read("pointer", pointer_);
            reader.Read("phase", phase_);
            reader.Read("read_mode", read_mode_);
            reader.Read("bus_open", open_);
            reader.Read("bus_timed_out", timed_out_);
            reader.Read("bus_stop_seen", stop_seen_);
            reader.Read("bus_seconds", seconds);
            reader.Read("bus_phase", phase);
            reader.Read("bus_phase_den", den);
            SetWindowRatio();
            window_.AnchorAtPhase(clock_->Cycles(), seconds, phase, den);
        }
        core_->RestoreState(reader);
    }

    void PostRestore() override { core_->PostRestore(); }

private:
    void IncrementPointer() { pointer_ = static_cast<uint8_t>((pointer_ + 1u) & 0x0Fu); }

    void SetWindowRatio() {
        if (!window_.SetRatio(clock_->CpuHz(), 1u)) RatioOverflow();
    }

    [[noreturn]] void RatioOverflow() const {
        emu_.Get<Fatal>().Die("RTC8564: the %llu Hz CPU clock overflows the bus timeout ratio",
                              static_cast<unsigned long long>(clock_->CpuHz()));
    }

    void Open(uint64_t now) {
        open_      = true;
        timed_out_ = false;
        stop_seen_ = core_->StopSet();
        SetWindowRatio();
        window_.Anchor(now, 0u);
    }

    /* Epson RTC-8564 ETM11J-07 section 13.6.3 note 3) (p. 33): 1 s from START to
       STOP releases the interface to standby, writes are invalid and reads return
       all 1s until a new START; section 13.1.1 (p. 12): STOP = 1 disables it. */
    bool TimedOut(uint64_t now) {
        if (!open_ || timed_out_ || window_.CountAt(now) == 0u || core_->StopSet()) {
            return timed_out_;
        }
        if (stop_seen_) {
            emu_.Get<Fatal>().Die("RTC8564: I2C transfer %u s after START with STOP set and "
                                  "cleared since that START; whether STOP restarts the bus "
                                  "timeout is not modelled", window_.CountAt(now));
        }
        timed_out_ = true;
        return true;
    }

    void OnRateChange() {
        std::lock_guard<std::mutex> guard(mutex_);
        if (open_ && !window_.Rescale(clock_->Cycles(), clock_->CpuHz(), 1u)) RatioOverflow();
    }

    GuestCycleClock*     clock_ = nullptr;
    Rtc8564Core*         core_  = nullptr;
    CycleAnchoredCounter window_;
    uint8_t              pointer_   = 0;
    uint32_t             phase_     = 0;
    bool                 read_mode_ = false;
    bool                 open_      = false;
    bool                 timed_out_ = false;
    bool                 stop_seen_ = false;
    std::mutex           mutex_;
};

REGISTER_SERVICE_AS(Rtc8564Interface, Iop13xxI2cDevice);

} // namespace
