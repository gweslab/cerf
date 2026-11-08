#pragma once

#include <cerfcore/core/service.h>

#include <atomic>
#include <cstdint>

namespace cerfcore {
class StateWriter;
class StateReader;
}

namespace cerffrontend {

class StylusAltTap : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnShutdown() override;

    bool Supported() const;
    bool Armable() const;

    bool Enabled() const { return enabled_.load(std::memory_order_acquire); }
    void SetEnabled(bool on) { enabled_.store(on, std::memory_order_release); }

    bool Begin(int guest_x, int guest_y);
    bool Running() const { return CurrentPhase() != Phase::Idle; }
    void Cancel();

    void SaveState(cerfcore::StateWriter& w) const;
    void RestoreState(cerfcore::StateReader& r);

private:
    enum class Phase { Idle, AltLead, PenHold, AltTrail };

    void Arm(uint32_t ms, Phase next);
    void Disarm() { timer_gen_.fetch_add(1u, std::memory_order_acq_rel); }
    void OnTimer(uint32_t gen);
    void UnwindHeld();

    Phase CurrentPhase() const { return phase_.load(std::memory_order_acquire); }
    void  SetPhase(Phase p) { phase_.store(p, std::memory_order_release); }

    std::atomic<Phase>    phase_{Phase::Idle};
    std::atomic<uint32_t> restore_gen_{0};
    std::atomic<uint32_t> timer_gen_{0};
    int                   tap_x_ = 0;
    int                   tap_y_ = 0;

    std::atomic<bool> enabled_{true};
};

}
