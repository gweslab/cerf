#pragma once

#include "../../core/service.h"
#include "../../socs/cycle_anchored_counter.h"
#include "sa1111_sbi.h"

#include <cstdint>

class StateReader;
class StateWriter;

class Sa1111SacTxStream : public Service {
public:
    using Service::Service;

    /* SA-1111 Developer's Manual §7.3.1: "FIFO buffers are 16 words deep". */
    static constexpr uint32_t kFifoDepth = 16u;
    /* §7.2.2: "Data transfers can be read or write bursts up to eight words long." */
    static constexpr uint32_t kMaxBurst = 8u;

    bool ShouldRegister() override;
    void OnReady() override;

    bool SetRatio(uint64_t cpu_hz, uint32_t cas, uint64_t fs_num, uint64_t fs_den);
    bool Rescale(uint64_t now, uint64_t cpu_hz, uint32_t cas, uint64_t fs_num, uint64_t fs_den);
    void RequireInFlightTiming(uint64_t now, uint64_t cpu_hz) const;
    void Settle(uint64_t now);
    void SetGrant(uint64_t now, Sa1111Sbi::BusGrant grant, bool checked);
    Sa1111Sbi::BusGrant Grant() const { return grant_; }

    void Run(uint64_t now);
    void Hold(uint64_t now);
    bool Running() const { return running_; }
    uint64_t Position(uint64_t now) const;
    uint64_t Requests() const { return requests_; }

    void StartBlock(uint64_t now);
    bool Fill(uint64_t now, uint32_t threshold, uint32_t& words_left);
    bool DoneCycle(uint64_t now, uint32_t threshold, uint32_t words_left, uint64_t& cycle) const;
    uint64_t LandedCycle() const;
    void Clear(uint64_t now);
    void ClearUnderrun(uint64_t now);
    uint32_t Level(uint64_t now) const;
    bool     Underrun(uint64_t now) const;
    bool     ServiceRequest(uint64_t now, bool enabled, uint32_t threshold) const;
    uint32_t StatusBits(uint64_t now, bool enabled, uint32_t threshold) const;

    void Save(StateWriter& w, uint64_t now) const;
    void Restore(StateReader& r, uint64_t now);

private:
    struct Request {
        uint64_t issue    = 0;
        uint64_t hz       = 0;
        uint32_t cas      = 0;
        uint32_t burst[2] = {};
    };

    struct StepState {
        uint64_t pushed    = 0;
        uint64_t start     = 0;
        uint64_t requests  = 0;
        uint64_t last_base = 0;
        Request  last;
    };

    uint64_t Consumed(uint64_t now) const;
    uint64_t ConsumeCycle(uint64_t words) const;
    uint64_t RequestCycle(uint64_t at) const;
    uint64_t WordLandCycle(const Request& rq, uint32_t word) const;
    uint32_t Unlanded(uint64_t now) const;
    bool     InFlightGap(uint64_t now) const;
    void     ResolveGap(uint64_t now);
    bool     RequestDue(uint64_t now, uint32_t threshold) const;
    bool     Step(uint32_t threshold, uint32_t& words_left, uint64_t limit, bool bounded,
                  StepState& s) const;

    static uint32_t Words(const Request& rq) { return rq.burst[0] + rq.burst[1]; }

    Sa1111Sbi* sbi_ = nullptr;
    CycleAnchoredCounter frames_;
    Request  last_;
    uint64_t last_base_   = 0;
    uint64_t start_cycle_ = 0;
    bool     resolved_    = true;
    uint64_t cpu_hz_ = 0;
    uint32_t cas_    = 0;
    uint64_t fs_num_ = 0;
    uint64_t fs_den_ = 0;
    uint64_t base_   = 0;
    bool     running_ = false;
    uint64_t skip_    = 0;
    uint64_t held_    = 0;
    uint64_t pushed_  = 0;
    uint64_t start_   = 0;
    uint64_t requests_ = 0;
    bool     underrun_ = false;
    Sa1111Sbi::BusGrant grant_ = Sa1111Sbi::BusGrant::Stalled;
    bool     stalled_request_ = false;
};
