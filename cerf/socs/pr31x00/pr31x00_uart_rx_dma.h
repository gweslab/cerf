#pragma once

#include "../../jit/guest_cycle_clock.h"
#include "../../jit/host_request_channel.h"
#include "../cycle_anchored_counter.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <vector>

class CerfEmulator;
class StateReader;
class StateWriter;

/* One UART's receive DMA channel (TMPR3911 §16.2.4, Fig 16.2.1). The engine has no view
   of the driver's read cursor and no way to stall the sender: it clocks received bytes
   into the buffer at the line rate and wraps under ENDMALOOP, overrunning unread bytes
   if the driver falls behind. */
class Pr31x00UartRxDma {
public:
    /* The engine's three interrupt outputs (Fig 16.2.1): a byte loaded into the Receive
       Holding Register, and the address counter reaching the mid point and the end of
       the buffer. */
    struct RxInts {
        bool rx        = false;
        bool dma_half  = false;
        bool dma_full  = false;
    };
    using RxIntFn    = std::function<void(const RxInts&)>;
    using LineIdleFn = std::function<void()>;

    struct LineTiming {
        GuestCycleClock::Rate uart_clock{0u, 1u};
        uint64_t              uart_clocks_per_bit = 0;
        uint32_t              frame_bits          = 0;
        uint32_t              transfer_bits       = 0;
    };

    Pr31x00UartRxDma(CerfEmulator& emu, const char* source);

    void Attach(RxIntFn raise_ints, LineIdleFn on_line_idle);

    void SetBuffer(uint32_t pa);
    void SetLength(uint32_t bytes);
    void SetArmed(bool armed);
    void SetLine(const LineTiming& timing);

    uint32_t Count() const;
    uint32_t Length() const;
    bool     LineIdle() const;

    void Receive(const uint8_t* data, size_t n);

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);

private:
    void OnHostRequest();
    void OnCharEvent();
    void StartRunLocked(uint64_t now);
    void StopRunLocked();
    void ClockRunLocked(uint64_t now);
    void SetBitRatioLocked();
    bool ReachedLocked(uint64_t now) const;
    void ArmLocked(uint64_t now);

    CerfEmulator& emu_;
    const char*   source_;

    mutable std::mutex mu_;

    uint32_t buffer_pa_ = 0;
    uint32_t length_    = 0;
    uint32_t count_     = 0;
    bool     armed_     = false;

    std::vector<uint8_t> wire_;
    size_t               wire_pos_ = 0;

    LineTiming              timing_;
    CycleAnchoredCounter    bits_;
    bool                    busy_       = false;
    bool                    clocked_    = false;
    uint32_t                next_bit_   = 0;
    uint32_t                held_count_ = 0;
    uint64_t                held_phase_ = 0;
    uint64_t                held_den_   = 1;
    GuestCycleClock*        clock_      = nullptr;
    HostRequestChannel*     host_requests_ = nullptr;
    GuestCycleClock::Event* event_      = nullptr;

    RxIntFn    raise_ints_;
    LineIdleFn on_line_idle_;
};
