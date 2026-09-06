#pragma once

#define NOMINMAX
#include <windows.h>

#include "../core/service.h"

#include <atomic>

class StateWriter;
class StateReader;

class StylusAltTap : public Service {
public:
    using Service::Service;

    void OnShutdown() override;

    bool Supported() const;
    bool Armable() const;

    bool Enabled() const { return enabled_.load(std::memory_order_acquire); }
    void SetEnabled(bool on) { enabled_.store(on, std::memory_order_release); }

    bool Begin(int guest_x, int guest_y);
    bool Running() const { return CurrentPhase() != Phase::Idle; }
    bool OnTimer(UINT_PTR timer_id);
    void Cancel();

    void SaveState(StateWriter& w) const;
    void RestoreState(StateReader& r);

private:
    enum class Phase { Idle, AltLead, PenHold, AltTrail };

    void Arm(UINT ms, Phase next);
    void UnwindHeld();

    Phase CurrentPhase() const { return phase_.load(std::memory_order_acquire); }
    void  SetPhase(Phase p) { phase_.store(p, std::memory_order_release); }

    std::atomic<Phase> phase_{Phase::Idle};
    int                tap_x_ = 0;
    int                tap_y_ = 0;

    std::atomic<bool> enabled_{true};
};
