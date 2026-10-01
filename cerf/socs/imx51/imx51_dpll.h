#pragma once

#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_base.h"
#include "../oscillator_ticks.h"

#include <array>
#include <cstdint>

class Imx51Dpll : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

    uint64_t OutputHz() const;
    bool     OutputKnown() const { return output_known_ || lock_ == Lock::kRelocking; }

private:
    static constexpr uint32_t kSize = 0x00001000u;

    enum class Lock : uint8_t { kOff, kRelocking, kLocked, kBroken };

    void     ResetRegisters();
    void     Restart(bool was_enabled, bool by_rst);
    void     OnLock();
    void     SetOutput(uint64_t hz);
    uint64_t ReferenceHz() const;
    uint64_t ComputeHz() const;

    std::array<uint32_t, kSize / 4> regs_{};
    bool                    output_known_ = false;
    uint64_t                output_hz_    = 0;
    Lock                    lock_         = Lock::kOff;
    uint64_t                target_hz_    = 0;
    uint64_t                lock_tick_    = 0;
    GuestCycleClock*        clock_        = nullptr;
    GuestCycleClock::Event* lock_event_   = nullptr;
    OscillatorTicks         ref_{emu_, false};
};
