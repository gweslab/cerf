#pragma once

#include "../../core/service.h"
#include "../../jit/guest_cycle_clock.h"
#include "../dma_burst_fifo.h"
#include "../rated_tick_count.h"
#include "../serial_shifter_run.h"
#include "sa11xx_dma_clients.h"
#include "sa11xx_dma_port.h"
#include "sa11xx_uart_regs.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <vector>

class Sa11xxDma;
class Sa11xxUartBase;
class StateReader;
class StateWriter;

class Sa11xxUartTransmitter : public Service, public Sa11xxDmaTransmitObserver {
public:
    using Bytes   = std::vector<uint8_t>;
    using Control = sa11xx_uart::Control;

    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t Attach(Sa11xxUartBase* owner, uint32_t utdr, uint32_t device_select,
                    const char* name);
    bool WriteControl(uint32_t port, uint64_t now, const Control& c, Bytes& out);
    void Write(uint32_t port, uint64_t now, uint8_t value, Bytes& out);
    void Settle(uint32_t port, uint64_t now, Bytes& out);
    void Reset(uint32_t port);
    void NotifyDma();

    bool Tfs(uint32_t port) const { return ch_[port]->tfs.load(std::memory_order_acquire); }
    bool Tby(uint32_t port) const { return !ch_[port]->line_end.empty(); }
    bool Tnf(uint32_t port) const;

    void OnTransmitBlock(uint32_t ddar, uint32_t pa, uint32_t bytes,
                         GuestCycleClock::Rate word_rate) override;
    void OnTransmitStop(uint32_t) override {}
    void OnTransmitRestored() override {}

    void Save(uint32_t port, StateWriter& w);
    void Restore(uint32_t port, StateReader& r);
    void PostRestore(uint32_t port);

private:
    static constexpr uint32_t kPorts   = 3u;
    static constexpr uint64_t kNoCycle = UINT64_MAX;

    struct Channel;

    class Port : public Sa11xxDmaPort {
    public:
        Port(Sa11xxUartTransmitter& t, uint32_t index) : t_(t), index_(index) {}
        uint32_t DeviceAddress() const override;
        bool     Receive() const override { return false; }
        uint32_t DatumBytes() const override { return 1u; }
        void     Settle(uint64_t now) override { t_.PortSettle(index_, now); }
        void     SetSupply(uint64_t now, uint64_t words) override {
            t_.SetDmaSupply(index_, now, words);
        }
        uint64_t Moved() const override { return t_.ch_[index_]->fifo.Moved(); }
        bool     CycleOfMoved(uint64_t words, uint64_t& cycle) override {
            return t_.CycleOfMoved(index_, words, cycle);
        }
        GuestCycleClock::Rate WordRate() const override { return t_.FrameRate(*t_.ch_[index_]); }

    private:
        Sa11xxUartTransmitter& t_;
        const uint32_t         index_;
    };

    struct Channel {
        Channel(Sa11xxUartTransmitter& t, uint32_t index) : port(t, index) {}
        Port                    port;
        Sa11xxUartBase*         owner = nullptr;
        const char*             name  = "";
        uint32_t                utdr  = 0;
        uint32_t                ds    = 0;
        GuestCycleClock::Event* ev    = nullptr;
        Control                 ctl{};
        RatedTickCount          bits;
        DmaBurstFifo            fifo;
        SerialShifterRun        run;
        std::deque<uint8_t>     data;
        std::deque<uint8_t>     dma_bytes;
        std::deque<uint8_t>     line_bytes;
        std::deque<uint64_t>    line_end;
        uint64_t                dma_pulled = 0;
        uint64_t                dma_supply = 0;
        uint64_t                armed      = kNoCycle;
        bool                    clocked    = false;
        std::atomic<bool>       tfs{false};
    };

    static uint64_t FrameBits(const Channel& c);
    static GuestCycleClock::Rate BitRate(const Channel& c);
    static GuestCycleClock::Rate FrameRate(const Channel& c);

    void SettleChannel(Channel& c, uint64_t now, Bytes& out);
    void PullDma(Channel& c);
    void StartBaud(Channel& c, uint64_t now);
    void StartRun(Channel& c, uint64_t now);
    void StopTransmit(Channel& c);
    void Publish(Channel& c);
    void Arm(Channel& c, uint64_t now);
    void PortSettle(uint32_t port, uint64_t now);
    void SetDmaSupply(uint32_t port, uint64_t now, uint64_t words);
    bool CycleOfMoved(uint32_t port, uint64_t words, uint64_t& cycle);
    void OnEvent(uint32_t port);
    void OnCpuRate();

    GuestCycleClock* clock_ = nullptr;
    Sa11xxDma*       dma_   = nullptr;
    std::array<std::unique_ptr<Channel>, kPorts> ch_{};
    uint32_t         count_ = 0;
};
