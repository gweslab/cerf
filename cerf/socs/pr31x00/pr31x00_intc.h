#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>
#include <functional>
#include <mutex>
#include <vector>

class MipsJit;

/* Philips PR31x00 Interrupt Module, TMPR3911/3912 ch.8. */
class Pr31x00Intc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x10C00100u; }
    uint32_t MmioSize() const override { return 0x30u; }

    uint32_t ReadWord(uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    uint8_t  ReadByte(uint32_t addr) override { HaltUnsupportedAccess("PR31x00 INTC ReadByte", addr, 0); }
    uint16_t ReadHalf(uint32_t addr) override { HaltUnsupportedAccess("PR31x00 INTC ReadHalf", addr, 0); }
    void WriteByte(uint32_t addr, uint8_t  v) override { HaltUnsupportedAccess("PR31x00 INTC WriteByte", addr, v); }
    void WriteHalf(uint32_t addr, uint16_t v) override { HaltUnsupportedAccess("PR31x00 INTC WriteHalf", addr, v); }

    /* Latch a pending event into Status set `set` (0-4 == Interrupt Status 1-5).
       A Status bit is set by its source event and cleared only by a write to the
       matching Clear Interrupt Register (§8.2.2). */
    void SetPending(uint32_t set, uint32_t bits);

    /* Deassert a source's request: a device that resets or loses power drops its
       interrupt line along with the data behind it. */
    void ClearPending(uint32_t set, uint32_t bits);

    void SetSourceFreeRunning(uint32_t set, uint32_t bits, bool active);

    /* GLOBALEN, Enable Interrupt 6 bit 18 (TMPR3911 §8.3.17). */
    void SetGlobalEnable();

    bool EnabledInterruptPending() const;
    bool SourceEnabledWithoutGlobalEnable() const;
    bool WouldRaiseIrq(uint32_t set, uint32_t bits) const;

    /* Notify `cb` when the guest unmasks any of `bits` in Enable Interrupt
       `set+1` (and once at registration if already unmasked). Fired OUTSIDE the
       lock: the callback re-enters via SetPending, which would deadlock the
       non-recursive INTC mutex if fired under it. */
    void RegisterEnableListener(uint32_t set, uint32_t bits, std::function<void()> cb);

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

private:
    mutable std::mutex mtx_;

    uint32_t status_[5]       = {};
    uint32_t enable_[5]       = {};
    uint32_t free_running_[5] = {};
    uint32_t enable6_         = 0;   /* GLOBALEN cleared on power-on reset (§8.3.17) */

    struct EnableListener { uint32_t set; uint32_t bits; std::function<void()> cb; };
    std::vector<EnableListener> enable_listeners_;

    MipsJit* jit_ = nullptr;

    bool     IrqLowFor(const uint32_t* status) const;
    bool     IrqHighFor(const uint32_t* status) const;
    uint32_t HighPriorityLevelFor(const uint32_t* status) const;
    void RecomputeLocked();
};
