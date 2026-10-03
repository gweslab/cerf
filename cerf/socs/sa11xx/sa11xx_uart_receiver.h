#pragma once

#include "../../core/service.h"
#include "../../jit/guest_cycle_clock.h"
#include "../rated_tick_count.h"
#include "sa11xx_dma_port.h"
#include "sa11xx_uart_regs.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <vector>

class HostRequestChannel;
class Sa11xxDma;
class Sa11xxUartBase;
class StateReader;
class StateWriter;

class Sa11xxUartReceiver : public Service {
public:
    using Control = sa11xx_uart::Control;

    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t Attach(Sa11xxUartBase* owner, uint32_t utdr, uint32_t device_select,
                    const char* name);
    void     Push(uint32_t port, const uint8_t* data, size_t n);
    void     WriteControl(uint32_t port, uint64_t now, const Control& c);
    void     Settle(uint32_t port, uint64_t now);
    uint8_t  Pop(uint32_t port, uint64_t now);
    uint32_t Utsr0(uint32_t port) const;
    uint32_t Utsr1(uint32_t port) const;
    void     ClearStatus(uint32_t port, uint64_t now, uint32_t mask);
    bool     InterruptRequest(uint32_t port) const;
    void     Reset(uint32_t port);

    void Save(uint32_t port, StateWriter& w);
    void Restore(uint32_t port, StateReader& r);
    void PostRestore(uint32_t port);

private:
    static constexpr uint32_t kPorts = 3u;
    static constexpr uint64_t kNever = UINT64_MAX;

    class Port : public Sa11xxDmaPort {
    public:
        Port(Sa11xxUartReceiver& r, uint32_t index) : r_(r), index_(index) {}
        uint32_t DeviceAddress() const override;
        bool     Receive() const override { return true; }
        uint32_t DatumBytes() const override { return 1u; }
        void     Settle(uint64_t now) override { r_.Settle(index_, now); }
        void     SetSupply(uint64_t now, uint64_t words) override {
            r_.SetDmaSupply(index_, now, words);
        }
        uint64_t Moved() const override { return 0u; }
        bool     CycleOfMoved(uint64_t words, uint64_t& cycle) override;
        GuestCycleClock::Rate WordRate() const override;

    private:
        Sa11xxUartReceiver& r_;
        const uint32_t      index_;
    };

    struct Channel {
        Channel(Sa11xxUartReceiver& r, uint32_t index) : port(r, index) {}
        Port                    port;
        Sa11xxUartBase*         owner = nullptr;
        const char*             name  = "";
        uint32_t                utdr  = 0;
        GuestCycleClock::Event* ev    = nullptr;
        Control                 ctl{};
        RatedTickCount          bits;
        bool                    clocked = false;
        std::deque<uint16_t>    fifo;
        std::deque<uint64_t>    line_end;
        std::deque<uint8_t>     line_bytes;
        uint64_t                next_start = 0;
        bool                    rid      = false;
        uint64_t                rid_tick = kNever;
        uint64_t                dma_supply = 0;
        std::mutex              wire_mtx;
        std::vector<uint8_t>    wire;
    };

    static uint64_t FrameBits(const Channel& c);
    static bool Rfs(const Channel& c);
    static bool Eif(const Channel& c);

    void Accept(Channel& c, uint64_t now);
    void SettleChannel(Channel& c, uint64_t now);
    void Store(Channel& c, uint8_t byte);
    void CheckIdle(Channel& c, uint64_t tick);
    void StopReceive(Channel& c);
    void Arm(Channel& c, uint64_t now);
    void SetDmaSupply(uint32_t port, uint64_t now, uint64_t words);
    void OnHostRequest();
    void OnEvent(uint32_t port);
    void OnCpuRate();

    GuestCycleClock*    clock_    = nullptr;
    HostRequestChannel* requests_ = nullptr;
    std::array<std::unique_ptr<Channel>, kPorts> ch_{};
    uint32_t            count_ = 0;
};
