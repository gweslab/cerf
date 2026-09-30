#pragma once

#include "../core/service.h"
#include "../jit/guest_cycle_clock.h"
#include "intel_os_timer_census.h"

#include <cstdint>

class StateReader;
class StateWriter;

struct IntelOsTimerRearm {
    uint32_t target = 0;
    uint32_t bank   = 0;
    uint32_t period = 0;
};

struct IntelOsTimerOsmrWrite {
    bool walk_away = false;
    bool absorb    = false;
};

class IntelOsTimerKernelInvariants : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    bool OnMaskedPair(bool oie0, uint32_t pair_oscr, IntelOsTimerCensus& census,
                      IntelOsTimerRearm& rearm);
    IntelOsTimerOsmrWrite OnChannel0Write(uint32_t step, bool status0,
                                          IntelOsTimerCensus& census);
    bool     WalkAway(uint32_t ahead, IntelOsTimerCensus& census);
    uint32_t Absorb(uint32_t value, uint32_t oscr, bool bank_pair_since_match,
                    IntelOsTimerCensus& census);
    void     OnTickAck();
    bool     OnMatch(int n, uint32_t osmr_n, bool oie0, IntelOsTimerCensus& census,
                     IntelOsTimerRearm& rearm);

    void ForgetCounterDomain();
    void ForgetGuestSequence();

    void Save(StateWriter& w) const;
    void Restore(StateReader& r);

private:
    void     TakeOmittedExitRearm(IntelOsTimerCensus& census, IntelOsTimerRearm& rearm);
    uint32_t Tick() const;
    void     LearnPeriod(uint32_t step);

    GuestCycleClock* clock_ = nullptr;

    uint32_t last_match_oscr_[4] = {};
    bool     have_match_[4]      = {};

    uint32_t period_cand_             = 0;
    bool     bank_pending_            = false;
    uint32_t bank_oscr_               = 0;
    bool     have_period_             = false;
    uint32_t period_                  = 0;
    bool     isr_write_pending_       = false;
    bool     osmr0_written_since_ack_ = false;
    bool     last_write_rephased_     = false;
};
