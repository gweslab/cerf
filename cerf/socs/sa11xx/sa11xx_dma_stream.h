#pragma once

#include "../../jit/guest_cycle_clock.h"

#include <cstdint>
#include <functional>

class Sa11xxDmaPort;
class StateReader;
class StateWriter;

/* SA-1110 Developer's Manual §11.6.1.2 DCSRn bits. */
namespace sa11xx_dma {
constexpr uint32_t kRun   = 1u << 0;
constexpr uint32_t kIe    = 1u << 1;
constexpr uint32_t kError = 1u << 2;
constexpr uint32_t kDoneA = 1u << 3;
constexpr uint32_t kStrtA = 1u << 4;
constexpr uint32_t kDoneB = 1u << 5;
constexpr uint32_t kStrtB = 1u << 6;
constexpr uint32_t kBiu   = 1u << 7;

constexpr uint32_t Done(bool buffer_b) { return buffer_b ? kDoneB : kDoneA; }
constexpr uint32_t Strt(bool buffer_b) { return buffer_b ? kStrtB : kStrtA; }
}

struct Sa11xxDmaChannelRegs {
    uint32_t ddar = 0;
    uint32_t dcsr = 0;
    uint32_t dbsa = 0;
    uint32_t dbta = 0;
    uint32_t dbsb = 0;
    uint32_t dbtb = 0;
};

class Sa11xxDmaStream {
public:
    struct Hooks {
        std::function<void(uint32_t ddar, uint32_t pa, uint32_t bytes,
                           GuestCycleClock::Rate word_rate)> transmit;
        std::function<void(uint32_t ddar, uint32_t pa, uint32_t bytes,
                           GuestCycleClock::Rate word_rate)> receive;
    };

    static constexpr uint32_t kBurstDatums = 4u;

    static uint32_t Count(const Sa11xxDmaChannelRegs& r, bool buffer_b);
    static uint32_t Start(const Sa11xxDmaChannelRegs& r, bool buffer_b) {
        return buffer_b ? r.dbsb : r.dbsa;
    }
    static bool BufferValid(const Sa11xxDmaChannelRegs& r, bool buffer_b, uint32_t datum);

    void Bind(Sa11xxDmaPort* port) {
        if (port != port_) chained_ = false;
        port_ = port;
    }
    void Reset();
    Sa11xxDmaPort* Port() const { return port_; }
    bool Active() const { return active_; }
    bool ActiveBuffer() const { return cur_b_; }
    uint32_t WordsMoved(bool buffer_b) const { return moved_[buffer_b ? 1 : 0]; }

    void Evaluate(uint64_t now, Sa11xxDmaChannelRegs& r, const Hooks& hooks);
    void Abandon(uint64_t now, Sa11xxDmaChannelRegs& r, const Hooks& hooks);
    void FlushReceived(const Sa11xxDmaChannelRegs& r, const Hooks& hooks);
    bool ArmBuffer(const Sa11xxDmaChannelRegs& r, bool buffer_b);
    void Rewind(bool buffer_b);
    bool DoneCycle(uint64_t& cycle) const;

    void Save(StateWriter& w) const;
    void Restore(StateReader& r);

private:
    uint32_t Words(const Sa11xxDmaChannelRegs& r, bool b) const;
    uint32_t Datum() const;

    uint64_t Supply(const Sa11xxDmaChannelRegs& r) const;
    void     Begin(Sa11xxDmaChannelRegs& r, const Hooks& hooks);
    void     Complete(Sa11xxDmaChannelRegs& r, const Hooks& hooks);
    void     WriteReceived(const Sa11xxDmaChannelRegs& r, const Hooks& hooks, uint32_t upto);

    Sa11xxDmaPort* port_    = nullptr;
    bool     active_  = false;
    bool     chained_ = false;
    bool     cur_b_   = false;
    uint64_t origin_  = 0;
    uint64_t end_     = 0;
    uint32_t moved_[2]   = {};
    uint32_t written_[2] = {};
};
