#pragma once

#include "../../core/service.h"
#include "../../jit/guest_cycle_clock.h"

#include <cstdint>
#include <functional>

class Sa1111ResetLine;
class Sa1111SacHostOutput;
class Sa1111SacRequestLines;
class Sa1111SacTxStream;
class Sa1111Sbi;
class StateReader;
class StateWriter;

class Sa1111SacDma : public Service {
public:
    using Service::Service;

    struct FifoControl {
        bool     enabled         = false;
        uint32_t threshold_level = 0;
    };

    bool ShouldRegister() override;
    void OnReady() override;

    void SetFifoControlReader(std::function<FifoControl()> read);

    uint32_t ReadRegister(uint32_t off);
    void     WriteRegister(uint32_t off, uint32_t value);

    bool TransmitRunning() const { return tx_running_; }
    void Evaluate(uint64_t now);
    void CatchUp(uint64_t now);
    void OnClockChange() const;
    void Reset();

    void Save(StateWriter& w, uint64_t now);
    void Restore(StateReader& r);
    void PostRestore();

private:
    enum : uint32_t {                  /* SADTCS bits, Table 7-19. */
        kTden  = 1u << 0,
        kTdie  = 1u << 1,
        kTdbda = 1u << 3,
        kTdsta = 1u << 4,
        kTdbdb = 1u << 5,
        kTdstb = 1u << 6,
        kTbiu  = 1u << 7,
    };

    void     WriteSadtcs(uint32_t value);
    void     WriteSadrcs(uint32_t value);
    void     TryStartNext(uint64_t now);
    void     StartBlock(uint64_t now, bool buffer_b);
    void     ArmDone();
    void     CompleteBlock(uint64_t at, uint64_t seen);
    void     PublishDone(uint8_t completed);
    void     StopTransmit();
    void     RequireClocks() const;
    uint32_t Threshold() const;
    void     OnDoneEvent();
    void     OnGrantChange();

    std::function<FifoControl()> fifo_;
    GuestCycleClock*        clock_      = nullptr;
    GuestCycleClock::Event* done_ev_    = nullptr;
    Sa1111SacTxStream*      stream_     = nullptr;
    Sa1111SacRequestLines*  lines_      = nullptr;
    Sa1111SacHostOutput*    host_       = nullptr;
    Sa1111Sbi*              sbi_        = nullptr;
    Sa1111ResetLine*        reset_line_ = nullptr;
    bool     tx_running_  = false;
    bool     tx_buffer_b_ = false;
    uint32_t words_left_  = 0;
    bool     done_irq_a_  = false;
    bool     done_irq_b_  = false;

    uint32_t sadtcs_ = 0, sadtsa_ = 0, sadtca_ = 0, sadtsb_ = 0, sadtcb_ = 0;
    uint32_t sadrcs_ = 0, sadrsa_ = 0, sadrca_ = 0, sadrsb_ = 0, sadrcb_ = 0;
};
