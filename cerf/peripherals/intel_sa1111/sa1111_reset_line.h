#pragma once

#include "../../core/service.h"
#include "../../jit/guest_cycle_clock.h"
#include "sa1111_serial_transfer.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <vector>

class StateReader;
class StateWriter;

class Sa1111ResetLine : public Service {
public:
    explicit Sa1111ResetLine(CerfEmulator& emu);

    enum class Pin { Low, High, Floating };

    bool ShouldRegister() override;
    void OnReady() override;

    void RegisterListener(std::function<void(bool held)> fn);
    void Drive(Pin level, bool resync);
    void OnSkcrWrite(bool rclk_enabled, bool pll_selected);
    void SettleRelease();
    void RequireReleased(const char* unit, uint32_t addr) const;
    bool Held() const { return held_.load(std::memory_order_acquire); }
    bool PowerOnHoldPending() const { return power_on_pending_; }

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);

private:
    void Assert();
    void Release();

    std::vector<std::function<void(bool)>> listeners_;
    GuestCycleClock*     clock_ = nullptr;
    Sa1111SerialTransfer release_;
    Pin               pin_  = Pin::Floating;
    std::atomic<bool> held_{false};
    bool              power_on_pending_ = false;
    bool              release_pending_  = false;
};
