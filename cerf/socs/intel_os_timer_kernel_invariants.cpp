#include "intel_os_timer_kernel_invariants.h"

#include "../core/cerf_emulator.h"
#include "../boards/board_context.h"
#include "../state/state_stream.h"
#include "pxa255/pxa255_id.h"
#include "pxa27x/pxa270_id.h"
#include "sa11xx/sa1100_id.h"
#include "sa11xx/sa1110_id.h"

bool IntelOsTimerKernelInvariants::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    if (bd == nullptr) return false;
    const auto soc = bd->GetSocId();
    return soc == SocId::Sa1110 || soc == SocId::Sa1100 || soc == SocId::Pxa255 ||
           soc == SocId::Pxa270;
}

void IntelOsTimerKernelInvariants::OnReady() {
    clock_ = &emu_.Get<GuestCycleClock>();
}

bool IntelOsTimerKernelInvariants::OnMaskedPair(bool oie0, uint32_t pair_oscr,
                                                IntelOsTimerCensus& census,
                                                IntelOsTimerRearm& rearm) {
    if (osmr0_written_since_ack_ && !last_write_rephased_) {
        ++census.pairs_post_grid_write;
        return false;
    }
    bool do_rearm = false;
    if (bank_pending_ && have_period_ && oie0) {
        TakeOmittedExitRearm(census, rearm);
        do_rearm = true;
    }
    bank_pending_ = true;
    bank_oscr_    = pair_oscr;
    ++census.banks;
    return do_rearm;
}

IntelOsTimerOsmrWrite IntelOsTimerKernelInvariants::OnChannel0Write(uint32_t step, bool status0,
                                                                    IntelOsTimerCensus& census) {
    IntelOsTimerOsmrWrite out;
    const bool rewrite = osmr0_written_since_ack_;
    if (isr_write_pending_) {
        LearnPeriod(step);
        isr_write_pending_ = false;
    }
    if (bank_pending_) ++census.resolved_write;
    bank_pending_            = false;
    osmr0_written_since_ack_ = true;
    last_write_rephased_     = !(have_period_ && step != 0u && step % period_ == 0u);
    const uint32_t tick = Tick();
    /* jornada720 jornada720.bin nk.exe sub_80075638 0x80075694-0x800756D4: the tick handler
       adds the period to OSMR0 until 20 <= OSMR0 - OSCR <= the period. */
    out.walk_away = rewrite && tick != 0u && step == tick;
    /* SA-1110 §9.4.4: the OSSR bit is set at the match and stays set until the guest writes a
       one. */
    if (have_period_ && have_match_[0] && !status0) {
        if (last_write_rephased_) out.absorb = true;
        else                      ++census.absorb_step;
    }
    return out;
}

bool IntelOsTimerKernelInvariants::WalkAway(uint32_t ahead, IntelOsTimerCensus& census) {
    if (static_cast<int32_t>(ahead) <= static_cast<int32_t>(Tick())) return false;
    census.OnWalkAway(ahead);
    return true;
}

/* SA-1110 §9.4.2: every OSMR is compared on each rising edge. */
uint32_t IntelOsTimerKernelInvariants::Absorb(uint32_t value, uint32_t oscr,
                                              bool bank_pair_since_match,
                                              IntelOsTimerCensus& census) {
    const uint32_t phase = oscr - last_match_oscr_[0];
    const uint32_t ahead = value - oscr;
    if (bank_pair_since_match) {
        last_match_oscr_[0] = oscr;
        census.OnAbsorbSkipped(phase);
        return 0u;
    }
    if (phase == 0u || phase >= ahead) {
        last_match_oscr_[0] = oscr;
        return 0u;
    }
    census.OnAbsorb(phase);
    last_match_oscr_[0] = oscr + phase;
    return phase;
}

void IntelOsTimerKernelInvariants::OnTickAck() {
    osmr0_written_since_ack_ = false;
}

bool IntelOsTimerKernelInvariants::OnMatch(int n, uint32_t osmr_n, bool oie0,
                                           IntelOsTimerCensus& census, IntelOsTimerRearm& rearm) {
    if (n == 0) {
        census.OnMatch0(bank_pending_);
        census.Report(clock_->NowNs(), period_);
        if (bank_pending_ && have_period_ && oie0) {
            TakeOmittedExitRearm(census, rearm);
            ++census.rearm_match;
            return true;
        }
        bank_pending_      = false;
        isr_write_pending_ = true;
    }
    last_match_oscr_[n] = osmr_n;
    have_match_[n]      = true;
    return false;
}

/* falcon_4220__4_10 nk.exe sub_800F5550 / symbol_mk500 nk.exe sub_801BD03C: OEMIdle banks
   (phase + accum) / P read through sub_800F5DE8 / sub_801BD5DC and returns without re-arming
   OSMR0 when the bank consumes the deadline. */
void IntelOsTimerKernelInvariants::TakeOmittedExitRearm(IntelOsTimerCensus& census,
                                                        IntelOsTimerRearm& rearm) {
    rearm.target  = bank_oscr_ + period_;
    rearm.bank    = bank_oscr_;
    rearm.period  = period_;
    bank_pending_ = false;
    ++census.rearm;
}

uint32_t IntelOsTimerKernelInvariants::Tick() const {
    return have_period_ ? period_ : period_cand_;
}

void IntelOsTimerKernelInvariants::LearnPeriod(uint32_t step) {
    if (have_period_) return;
    if (step != 0u && step == period_cand_) {
        period_      = step;
        have_period_ = true;
    }
    period_cand_ = step;
}

void IntelOsTimerKernelInvariants::ForgetCounterDomain() {
    for (int n = 0; n < 4; ++n) have_match_[n] = false;
    ForgetGuestSequence();
}

void IntelOsTimerKernelInvariants::ForgetGuestSequence() {
    bank_pending_            = false;
    have_period_             = false;
    period_cand_             = 0u;
    isr_write_pending_       = false;
    osmr0_written_since_ack_ = false;
    last_write_rephased_     = false;
}

void IntelOsTimerKernelInvariants::Save(StateWriter& w) const {
    for (int n = 0; n < 4; ++n) w.Write<uint32_t>("last_match_oscr", last_match_oscr_[n]);
    for (int n = 0; n < 4; ++n) w.Write<uint8_t>("have_match", have_match_[n] ? 1u : 0u);
    w.Write<uint32_t>("period_cand", period_cand_);
    w.Write<uint8_t>("bank_pending", bank_pending_ ? 1u : 0u);
    w.Write<uint32_t>("bank_oscr", bank_oscr_);
    w.Write<uint8_t>("have_period", have_period_ ? 1u : 0u);
    w.Write<uint32_t>("period", period_);
    w.Write<uint8_t>("isr_write_pending", isr_write_pending_ ? 1u : 0u);
    w.Write<uint8_t>("osmr0_written_since_ack", osmr0_written_since_ack_ ? 1u : 0u);
    w.Write<uint8_t>("last_write_rephased", last_write_rephased_ ? 1u : 0u);
}

void IntelOsTimerKernelInvariants::Restore(StateReader& r) {
    for (int n = 0; n < 4; ++n) r.Read("last_match_oscr", last_match_oscr_[n]);
    for (int n = 0; n < 4; ++n) {
        uint8_t v = 0;
        r.Read("have_match", v);
        have_match_[n] = v != 0u;
    }
    uint8_t flag = 0;
    r.Read("period_cand", period_cand_);
    r.Read("bank_pending", flag);
    bank_pending_ = flag != 0u;
    r.Read("bank_oscr", bank_oscr_);
    r.Read("have_period", flag);
    have_period_ = flag != 0u;
    r.Read("period", period_);
    r.Read("isr_write_pending", flag);
    isr_write_pending_ = flag != 0u;
    r.Read("osmr0_written_since_ack", flag);
    osmr0_written_since_ack_ = flag != 0u;
    r.Read("last_write_rephased", flag);
    last_write_rephased_ = flag != 0u;
}

REGISTER_SERVICE(IntelOsTimerKernelInvariants);
