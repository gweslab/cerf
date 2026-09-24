#include "pr31x00_uart_rx_dma.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"

#include <utility>

namespace {

/* A byte takes 87 us at 115200, far below what the pacing thread can be woken at, so
   each tick clocks in the bytes its elapsed time has earned. */
constexpr auto kTick = std::chrono::milliseconds(1);

/* A feeder with no flow control (a host COM port) keeps handing over bytes for as long
   as the guest ignores the line; the driver counts what the receiver drops
   (SerialGetDroppedByteNumber). */
constexpr size_t kWireMax = 64u * 1024u;

}  /* namespace */

Pr31x00UartRxDma::Pr31x00UartRxDma(CerfEmulator& emu, const char* source)
    : emu_(emu), source_(source) {}

Pr31x00UartRxDma::~Pr31x00UartRxDma() { Stop(); }

void Pr31x00UartRxDma::Start(RxIntFn raise_ints, LineIdleFn on_line_idle) {
    raise_ints_   = std::move(raise_ints);
    on_line_idle_ = std::move(on_line_idle);
    stop_         = false;
    last_         = Clock::now();
    pacer_        = std::thread([this] { PaceLoop(); });
}

void Pr31x00UartRxDma::Stop() {
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (stop_) return;
        stop_ = true;
    }
    cv_.notify_all();
    if (pacer_.joinable()) pacer_.join();
}

void Pr31x00UartRxDma::SetBuffer(uint32_t pa) {
    std::lock_guard<std::mutex> lk(mu_);
    buffer_pa_ = pa;
}

void Pr31x00UartRxDma::SetLength(uint32_t bytes) {
    std::lock_guard<std::mutex> lk(mu_);
    length_ = bytes;
}

/* Enabling DMA reloads the address counter (Fig 16.2.1), so the buffer restarts at its
   base. Bytes still on the wire go with the receiver either way: a disarmed channel
   clocks nothing in. */
void Pr31x00UartRxDma::SetArmed(bool armed) {
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (armed == armed_) return;
        armed_ = armed;
        if (armed) count_ = 0;
        wire_.clear();
        wire_pos_ = 0;
        credit_   = 0.0;
        last_     = Clock::now();
    }
    cv_.notify_one();
}

void Pr31x00UartRxDma::SetLineRate(uint32_t baud, double bits_per_char) {
    std::lock_guard<std::mutex> lk(mu_);
    baud_          = baud;
    bits_per_char_ = bits_per_char;
}

uint32_t Pr31x00UartRxDma::Count() const {
    std::lock_guard<std::mutex> lk(mu_);
    return count_;
}

uint32_t Pr31x00UartRxDma::Length() const {
    std::lock_guard<std::mutex> lk(mu_);
    return length_;
}

bool Pr31x00UartRxDma::LineIdle() const {
    std::lock_guard<std::mutex> lk(mu_);
    return wire_pos_ >= wire_.size();
}

void Pr31x00UartRxDma::Receive(const uint8_t* data, size_t n) {
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (!armed_) return;   /* a CTL1 disarm raced the byte; the channel drops it */

        if (wire_.size() - wire_pos_ + n > kWireMax) {
            LOG(Caution, "[UART] %s RX overrun: the guest is not draining the DMA "
                         "buffer, dropping %zu bytes\n", source_, n);
            return;
        }
        if (wire_pos_ >= wire_.size()) {   /* the line was idle: this traffic starts now */
            wire_.clear();
            wire_pos_ = 0;
            credit_   = 0.0;
            last_     = Clock::now();
        }
        wire_.insert(wire_.end(), data, data + n);
    }
    cv_.notify_one();
}

void Pr31x00UartRxDma::PaceLoop() {
    auto& freeze = emu_.Get<EmulationFreeze>();
    for (;;) {
        {
            std::unique_lock<std::mutex> lk(mu_);
            cv_.wait(lk, [this] { return stop_ || wire_pos_ < wire_.size(); });
            if (stop_) return;
        }

        RxInts ints;
        bool   idle_now = false;
        {
            /* EmulationFreeze before mu_ (agent_docs/hibernation.md): a snapshot taken
               mid-batch would carry a buffer the guest never saw filled. */
            auto frozen = freeze.WorkerSection();
            {
                std::lock_guard<std::mutex> lk(mu_);
                ints     = MeterLocked();
                idle_now = ints.rx && wire_pos_ >= wire_.size();
            }
            if (ints.rx && raise_ints_) raise_ints_(ints);
        }
        if (idle_now && on_line_idle_) on_line_idle_();

        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait_for(lk, kTick, [this] { return stop_; });
        if (stop_) return;
    }
}

Pr31x00UartRxDma::RxInts Pr31x00UartRxDma::MeterLocked() {
    RxInts ints;
    if (!armed_) return ints;

    /* The pacing thread IS the wire's clock, so a host stall makes the emulated line
       run slow: it never earns more than the tick it just waited out. */
    auto dt = Clock::now() - last_;
    if (dt > kTick) dt = kTick;
    last_ = Clock::now();

    credit_ += std::chrono::duration<double>(dt).count() *
               static_cast<double>(baud_) / bits_per_char_;

    uint32_t     n    = static_cast<uint32_t>(credit_);
    const size_t left = wire_.size() - wire_pos_;
    if (static_cast<size_t>(n) > left) n = static_cast<uint32_t>(left);
    if (n == 0u) return ints;

    auto& mem = emu_.Get<EmulatedMemory>();
    for (uint32_t i = 0; i < n; ++i) {
        mem.WriteByte(buffer_pa_ + count_, wire_[wire_pos_++]);
        ++count_;
        /* The counter is compared against the buffer's mid point and its end (Fig
           16.2.1). WriteCtl1 admits RX DMA only with ENDMALOOP set, so the end wraps. */
        if (count_ == length_ / 2u) ints.dma_half = true;
        if (count_ >= length_) {
            ints.dma_full = true;
            count_        = 0;
        }
    }
    credit_ -= static_cast<double>(n);
    ints.rx = true;

    if (wire_pos_ >= wire_.size()) {
        wire_.clear();
        wire_pos_ = 0;
    }
    return ints;
}

void Pr31x00UartRxDma::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mu_);
    w.Write("buffer_pa", buffer_pa_);
    w.Write("length", length_);
    w.Write("count", count_);
    w.Write<uint8_t>("armed", armed_ ? 1u : 0u);
}

/* The endpoint that handed over the bytes still on the wire is rebuilt by the cradle,
   so the line comes back idle and its rate is re-applied from the restored registers. */
void Pr31x00UartRxDma::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mu_);
    r.Read("buffer_pa", buffer_pa_);
    r.Read("length", length_);
    r.Read("count", count_);
    uint8_t armed = 0;
    r.Read("armed", armed);
    armed_ = armed != 0u;

    wire_.clear();
    wire_pos_ = 0;
    credit_   = 0.0;
    last_     = Clock::now();
}
