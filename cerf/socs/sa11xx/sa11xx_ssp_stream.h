#pragma once

#include "../../core/service.h"
#include "../../jit/guest_cycle_clock.h"
#include "../dma_burst_fifo.h"
#include "../rated_tick_count.h"
#include "../serial_shifter_run.h"
#include "sa11xx_dma_port.h"

#include <cstdint>
#include <deque>

class Sa11xxDma;
class Sa11xxGpio;
class Sa11xxIntc;
class Sa11xxMcp;
class Sa11xxPpc;
class Sa11xxSspBitClock;
class Sa11xxSspDevice;
class StateReader;
class StateWriter;

class Sa11xxSspStream : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    void     WriteControl(uint64_t now, uint32_t sscr0, uint32_t sscr1);
    void     WriteData(uint64_t now, uint16_t value);
    uint16_t ReadData(uint64_t now);
    uint32_t Status(uint64_t now);
    void     ClearOverrun(uint64_t now);
    void     RefreshLine(uint64_t now);

    void Save(StateWriter& w);
    void Restore(StateReader& r);

private:
    class Port : public Sa11xxDmaPort {
    public:
        Port(Sa11xxSspStream& s, bool receive) : s_(s), receive_(receive) {}
        uint32_t DeviceAddress() const override { return 0x81C01Bu; }
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
        Sa11xxSspStream& s_;
        const bool       receive_;
    };

    static constexpr uint64_t kNever = UINT64_MAX;

    void     BeforeClockChange(uint64_t now, bool stops);
    void     AfterClockChange(uint64_t now);
    uint64_t Frame() const;
    uint64_t DataFrameTicks() const;
    GuestCycleClock::Rate HalfBitRate() const;
    void     CheckPins() const;
    void     Settle(uint64_t now);
    void     SettleData(uint64_t now);
    void     SetSupply(uint64_t now, bool receive, uint64_t words);
    void     StartRun(uint64_t now);
    void     Disable();
    bool     TxCycleOfMoved(uint64_t words, uint64_t& cycle);
    bool     RxCycleOfMoved(uint64_t words, uint64_t& cycle);
    bool     PopTick(uint64_t pop, uint64_t& tick) const;
    bool     PushTick(uint64_t push, uint64_t& tick) const;
    bool     LineLevel() const;
    bool     NextRise(uint64_t& cycle) const;
    GuestCycleClock::Rate WordRate() const;

    GuestCycleClock*        clock_   = nullptr;
    GuestCycleClock::Event* line_ev_ = nullptr;
    Sa11xxIntc*             intc_    = nullptr;
    Sa11xxDma*              dma_     = nullptr;
    Sa11xxMcp*              mcp_     = nullptr;
    Sa11xxPpc*              ppc_     = nullptr;
    Sa11xxGpio*             gpio_    = nullptr;
    Sa11xxSspBitClock*      bit_     = nullptr;
    Sa11xxSspDevice*        device_  = nullptr;
    RatedTickCount        data_frame_;
    DmaBurstFifo          tx_;
    DmaBurstFifo          rx_;
    SerialShifterRun      tx_run_;
    Port                  tx_port_{*this, false};
    Port                  rx_port_{*this, true};
    std::deque<uint16_t>  rx_words_;
    uint32_t sscr0_      = 0;
    uint32_t sscr1_      = 0;
    bool     enabled_    = false;
    bool     ror_        = false;
    bool     data_busy_  = false;
    uint16_t data_word_  = 0;
    uint64_t rx_pushed_  = 0;
    uint64_t tx_supply_  = 0;
    uint64_t rx_supply_  = 0;
};
