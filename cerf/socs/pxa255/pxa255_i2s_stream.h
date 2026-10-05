#pragma once

#include "../../core/service.h"
#include "../../host/paced_wave_out.h"
#include "../../jit/guest_cycle_clock.h"
#include "../dma_burst_fifo.h"
#include "../pxa2xx/pxa2xx_dma_port.h"
#include "../pxa2xx/pxa2xx_frame_slot_law.h"
#include "../rated_tick_count.h"

#include <cstdint>
#include <vector>

class EmulatedMemory;
class Pxa255ClockManager;
class Pxa2xxDma;
class StateReader;
class StateWriter;

class Pxa255I2sStream : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;
    void OnShutdown() override;

    uint32_t Sacr0() const { return sacr0_; }
    uint32_t Sacr1() const { return sacr1_; }
    uint32_t Sadiv() const { return sadiv_; }
    bool     Enabled() const { return enabled_; }

    void     StoreSacr0(uint32_t value) { sacr0_ = value; }
    void     Enable(uint64_t now, uint32_t sacr0);
    void     WriteSacr1(uint64_t now, uint32_t value);
    void     StoreSadiv(uint32_t value) { sadiv_ = value; }
    void     WriteData(uint64_t now, uint32_t value);
    uint32_t ReadData(uint64_t now);
    void     ResetLine();

    void Save(StateWriter& w);
    void Restore(StateReader& r);

private:
    class Port : public Pxa2xxDmaPort {
    public:
        Port(Pxa255I2sStream& i2s, bool receive) : i2s_(i2s), receive_(receive) {}

        bool     Receive() const override { return receive_; }
        uint32_t FifoAddress() const override;
        void     Settle(uint64_t now) override { i2s_.Settle(now); }
        bool     RequestAsserted() const override;
        void     SetService(uint64_t now, uint32_t burst_words, uint64_t supply_words) override;
        uint64_t Moved() const override { return receive_ ? i2s_.rx_.Moved() : i2s_.tx_.Moved(); }
        bool     CycleOfMoved(uint64_t words, uint64_t& cycle) override {
            return receive_ ? i2s_.RxCycleOfMoved(words, cycle) : i2s_.TxCycleOfMoved(words, cycle);
        }
        void TransmitBlock(uint32_t pa, uint32_t bytes) override;
        void ReceiveBlock(uint32_t pa, uint32_t bytes) override;
        void Stopped(uint64_t now, bool end_of_chain) override;

    private:
        Pxa255I2sStream& i2s_;
        bool             receive_;
    };

    uint32_t TxThreshold() const { return (sacr0_ >> 8) & 0xFu; }
    uint32_t Rfth() const { return (sacr0_ >> 12) & 0xFu; }
    uint32_t RxFreeThreshold() const { return 15u - Rfth(); }
    uint32_t Replay() const;
    uint32_t Record() const;
    GuestCycleClock::Rate BitRate() const;

    bool UnitClockOn() const;
    void OnUnitClock();
    void Resume(uint64_t now);
    void Gate(uint64_t now);
    void ApplySacr1(uint64_t now, uint32_t old);
    static void ApplyFifoReset(uint32_t now_set, uint32_t was_set, uint64_t bits, uint64_t first, bool& pending,
                               uint64_t& frame, uint64_t& assert_bit);
    void Settle(uint64_t now);
    void TakeTo(uint64_t frames);
    void PushTo(uint64_t frames);
    bool TxCycleOfMoved(uint64_t words, uint64_t& cycle);
    bool RxCycleOfMoved(uint64_t words, uint64_t& cycle);
    void QueueHost(const void* bytes, uint32_t length);
    void OnCpuRate();

    GuestCycleClock*    clock_  = nullptr;
    EmulatedMemory*     mem_    = nullptr;
    Pxa2xxDma*          dma_    = nullptr;
    Pxa255ClockManager* clocks_ = nullptr;

    Port tx_port_{*this, false};
    Port rx_port_{*this, true};

    RatedTickCount     bits_;
    DmaBurstFifo       tx_;
    DmaBurstFifo       rx_;
    Pxa2xxFrameSlotLaw out_law_{1u};
    Pxa2xxFrameSlotLaw in_law_{1u};
    bool     enabled_          = false;
    bool     running_          = false;
    RatedTickCount::Position held_;
    uint32_t gated_sacr1_      = 0;
    uint64_t out_frames_       = 0;
    uint64_t in_frames_        = 0;
    bool     tx_reset_pending_ = false;
    bool     rx_reset_pending_ = false;
    uint64_t tx_reset_frame_   = 0;
    uint64_t rx_reset_frame_   = 0;
    uint64_t tx_assert_bit_    = 0;
    uint64_t rx_assert_bit_    = 0;

    uint32_t sacr0_ = 0, sacr1_ = 0, sadiv_ = 0;

    PacedWaveOut         host_;
    bool                 host_active_ = false;
    uint32_t             host_rate_   = 0;
    std::vector<uint8_t> block_;
};
