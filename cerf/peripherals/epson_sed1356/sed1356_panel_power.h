#pragma once

#include "../../core/service.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../socs/rated_tick_count.h"

#include <cstdint>
#include <mutex>

class Sed1356PowerSequence;
class StateReader;
class StateWriter;

class Sed1356PanelPower : public Service {
public:
    using Service::Service;

    struct Timing {
        GuestCycleClock::Rate pixel;
        uint64_t              frame_ticks   = 0;
        uint64_t              line_ticks    = 0;
        uint32_t              panel_divisor = 1;
        uint8_t               power_save_reg = 0;
    };

    bool ShouldRegister() override;
    void OnReady() override;

    void    PowerUp();
    void    PowerDown(bool lcd_disable, const Timing& t);
    void    Disturb();
    bool    Pending();
    bool    PowerDownInProgress();
    uint8_t VndWhileScanStopped();
    void    SetPixelRate(GuestCycleClock::Rate pixel);
    uint8_t StatusBits(uint8_t mode_reg, uint8_t power_save_reg, uint8_t refresh_reg);

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);
    void ResumeAfterRestore();

private:
    enum class State : uint8_t { Down = 0, Up = 1, PoweringDown = 2, Unknown = 3 };

    bool PendingLocked(uint64_t now) const;
    bool StatusPendingLocked(uint64_t now) const;
    bool SignalsActiveLocked(uint64_t now) const;
    void RescaleLocked(GuestCycleClock::Rate pixel);

    GuestCycleClock*            clock_ = nullptr;
    const Sed1356PowerSequence* seq_   = nullptr;
    std::mutex                  mtx_;
    State                       state_ = State::Down;
    RatedTickCount              ticks_;
    GuestCycleClock::Rate       pixel_;
    uint64_t                    status_after_    = 0;
    uint64_t                    signals_after_   = 0;
    bool                        signals_unknown_ = false;
    RatedTickCount::Position    held_;
};
