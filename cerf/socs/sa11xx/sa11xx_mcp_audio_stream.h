#pragma once

#include "../../core/service.h"
#include "../../jit/guest_cycle_clock.h"
#include "../dma_burst_fifo.h"
#include "../rated_tick_count.h"
#include "sa11xx_dma_port.h"
#include "sa11xx_mcp_receive_schedule.h"
#include "sa11xx_mcp_sample_counter.h"

#include <cstdint>

class Sa11xxDma;
class Sa11xxIntc;
class StateReader;
class StateWriter;

class Sa11xxMcpAudioStream : public Service {
public:
    static constexpr uint64_t kFrameTicks = 128u;

    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    void     WriteControl(uint64_t now, uint32_t mccr0, uint32_t mccr1);
    bool     CodecWrite(uint64_t now, uint32_t reg, uint16_t value);
    uint32_t Status(uint64_t now);
    void     ClearStatus(uint64_t now, uint32_t mask);
    bool     SclkTick(uint64_t now, uint64_t& tick) const;
    uint64_t NextFrameEdge(uint64_t now) const;
    uint64_t CycleOfSclk(uint64_t tick) const { return sclk_.CycleOfTick(tick); }
    uint32_t Run() const { return run_; }
    void     RefreshLine(uint64_t now);

    void Save(StateWriter& w);
    void Restore(StateReader& r);

private:
    class Port : public Sa11xxDmaPort {
    public:
        Port(Sa11xxMcpAudioStream& s, bool receive) : s_(s), receive_(receive) {}
        uint32_t DeviceAddress() const override { return 0x818002u; }
        bool     Receive() const override { return receive_; }
        uint32_t DatumBytes() const override { return 2u; }
        void     Settle(uint64_t now) override { s_.Settle(now); }
        void     SetSupply(uint64_t now, uint64_t words) override {
            s_.SetSupply(now, receive_, words);
        }
        uint64_t Moved() const override { return receive_ ? s_.rx_.Moved() : s_.tx_.Moved(); }
        bool     CycleOfMoved(uint64_t words, uint64_t& cycle) override {
            return receive_ ? s_.RxCycleOfMoved(words, cycle) : s_.TxCycleOfMoved(words, cycle);
        }
        GuestCycleClock::Rate WordRate() const override { return s_.WordRate(); }

    private:
        Sa11xxMcpAudioStream& s_;
        const bool            receive_;
    };

    static constexpr uint64_t kNever = UINT64_MAX;

    uint64_t SclkHz(uint32_t mccr1) const;
    uint64_t Period() const;
    void     Disable();
    void     Settle(uint64_t now);
    void     SetSupply(uint64_t now, bool receive, uint64_t words);
    bool     TxCycleOfMoved(uint64_t words, uint64_t& cycle);
    bool     RxCycleOfMoved(uint64_t words, uint64_t& cycle);
    bool     TakeTick(uint64_t take, uint64_t& tick) const;
    void     OpenReceive(uint64_t origin, uint64_t first_valid);
    bool     NextRise(uint64_t& tick) const;
    bool     LineLevel() const;
    void     OnCpuRate(uint64_t now);
    GuestCycleClock::Rate WordRate() const;

    GuestCycleClock*        clock_ = nullptr;
    GuestCycleClock::Event* line_ev_ = nullptr;
    Sa11xxDma*              dma_   = nullptr;
    Sa11xxIntc*             intc_  = nullptr;
    RatedTickCount          sclk_;
    DmaBurstFifo            tx_;
    DmaBurstFifo            rx_;
    Sa11xxMcpReceiveSchedule rx_schedule_;
    Sa11xxMcpSampleCounter  counter_;
    Port                    tx_port_{*this, false};
    Port                    rx_port_{*this, true};
    bool     enabled_   = false;
    bool     atu_       = false;
    bool     aro_       = false;
    bool     rx_armed_  = false;
    uint32_t mccr0_     = 0;
    uint32_t mccr1_     = 0;
    uint16_t codec_b_   = 0;
    uint64_t rx_pushed_ = 0;
    uint32_t run_       = 0;
};
