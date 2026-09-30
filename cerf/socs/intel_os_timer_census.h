#pragma once

#include "../core/log.h"

#include <cstdint>

struct IntelOsTimerCensus {
    void OnOsmr0Read(bool masked_pair, bool oscr_pending, bool ossr_set, bool masked_now) {
        if (masked_pair) {
            ++pairs;
            return;
        }
        if (!oscr_pending) return;
        if (ossr_set)  { ++pairs_acked;   return; }
        if (masked_now) { ++pairs_mixed;  return; }
        ++pairs_unmasked;
    }

    void OnAuxOsmrRead(bool oscr_pending) {
        ++aux_reads;
        if (oscr_pending) ++aux_reads_after_oscr;
    }

    void OnAbsorb(uint32_t phase_tk) {
        ++absorbs;
        absorb_tk += phase_tk;
    }

    void OnAbsorbSkipped(uint32_t phase_tk) {
        ++absorb_skipped;
        absorb_skipped_tk += phase_tk;
    }

    void OnWalkAway(uint32_t ahead_tk) {
        ++walkaways;
        walkaway_tk += ahead_tk;
    }

    void OnMatch0(bool bank_pending) {
        if (bank_pending) ++standing;
    }

    void Report(int64_t now_ns, uint32_t period) {
        if (report_ns == 0 || now_ns < report_ns) { report_ns = now_ns; return; }
        if (now_ns - report_ns < 1000000000ll) return;
        LOG(SocTimer, "[OSTXR] banks=%u resolved_by_write=%u rearm=%u (at match %u) "
                      "period=%u | census: masked_pairs=%u "
                      "standing_at_match=%u acked=%u mixed_masked=%u unmasked=%u "
                      "post_grid_write=%u | absorbs=%u absorb_tk=%llu "
                      "absorb_skipped=%u absorb_skipped_tk=%llu absorb_step=%u "
                      "aux_reads=%u aux_reads_after_oscr=%u rev_pairs=%u "
                      "walkaways=%u walkaway_tk=%llu osmr0_writes=%u tick_acks=%u\n",
            banks, resolved_write, rearm, rearm_match, period,
            pairs, standing, pairs_acked, pairs_mixed, pairs_unmasked,
            pairs_post_grid_write,
            absorbs, static_cast<unsigned long long>(absorb_tk), absorb_skipped,
            static_cast<unsigned long long>(absorb_skipped_tk), absorb_step,
            aux_reads, aux_reads_after_oscr, rev_pairs,
            walkaways, static_cast<unsigned long long>(walkaway_tk), osmr0_writes, tick_acks);
        osmr0_writes = tick_acks = 0u;
        rev_pairs = 0u;
        walkaways = 0u;
        walkaway_tk = 0u;
        banks = resolved_write = rearm = rearm_match = pairs_post_grid_write = 0u;
        pairs = standing = pairs_acked = pairs_mixed = pairs_unmasked = 0u;
        absorbs = absorb_skipped = absorb_step = 0u;
        absorb_tk = absorb_skipped_tk = 0u;
        aux_reads = aux_reads_after_oscr = 0u;
        report_ns = now_ns;
    }

    int64_t  report_ns             = 0;
    uint32_t banks                 = 0;
    uint32_t resolved_write        = 0;
    uint32_t rearm                 = 0;
    uint32_t rearm_match           = 0;
    uint32_t pairs_post_grid_write = 0;
    uint32_t pairs                 = 0;
    uint32_t standing              = 0;
    uint32_t pairs_acked           = 0;
    uint32_t pairs_mixed           = 0;
    uint32_t pairs_unmasked        = 0;
    uint32_t absorbs               = 0;
    uint64_t absorb_tk             = 0;
    uint32_t absorb_skipped        = 0;
    uint64_t absorb_skipped_tk     = 0;
    uint32_t absorb_step           = 0;
    uint32_t aux_reads             = 0;
    uint32_t aux_reads_after_oscr  = 0;
    uint32_t rev_pairs             = 0;
    uint32_t walkaways             = 0;
    uint64_t walkaway_tk           = 0;
    uint32_t osmr0_writes          = 0;
    uint32_t tick_acks             = 0;
};
