#include "pr31x00_uart_rx_dma.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../state/state_stream.h"

#include <utility>

namespace {

/* A feeder with no flow control (a host COM port) keeps handing over bytes for as long
   as the guest ignores the line; the driver counts what the receiver drops
   (SerialGetDroppedByteNumber). */
constexpr size_t kWireMax = 64u * 1024u;

}  /* namespace */

Pr31x00UartRxDma::Pr31x00UartRxDma(CerfEmulator& emu, const char* source)
    : emu_(emu), source_(source) {}

void Pr31x00UartRxDma::Attach(RxIntFn raise_ints, LineIdleFn on_line_idle) {
    raise_ints_   = std::move(raise_ints);
    on_line_idle_ = std::move(on_line_idle);
    clock_        = &emu_.Get<GuestCycleClock>();
    event_        = clock_->Add([this] { OnCharEvent(); });
    host_requests_ = &emu_.Get<HostRequestChannel>();
    host_requests_->RegisterListener([this] { OnHostRequest(); });
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
    std::lock_guard<std::mutex> lk(mu_);
    if (armed == armed_) return;
    armed_ = armed;
    if (armed) count_ = 0;
    wire_.clear();
    wire_pos_ = 0;
    StopRunLocked();
}

/* §16.2.2 p16-2: Baud Rate = f_UARTCLK / ((BAUDRATE + 1) * 16). */
void Pr31x00UartRxDma::SetBitRatioLocked() {
    const GuestCycleClock::Rate cpu  = clock_->ClockRate();
    const GuestCycleClock::Rate uart = timing_.uart_clock;
    const uint64_t per_bit = timing_.uart_clocks_per_bit;
    if (uart.den > UINT64_MAX / per_bit || uart.den * per_bit > UINT64_MAX / cpu.num ||
        cpu.den > UINT64_MAX / uart.num ||
        !bits_.SetRatio(cpu.num * uart.den * per_bit, cpu.den * uart.num)) {
        emu_.Get<Fatal>().Die("Pr31x00UartRxDma %s: the %llu/%llu Hz core against the %llu/%llu Hz "
                              "UART clock / %llu overflows the bit counter scale", source_,
                              static_cast<unsigned long long>(cpu.num),
                              static_cast<unsigned long long>(cpu.den),
                              static_cast<unsigned long long>(uart.num),
                              static_cast<unsigned long long>(uart.den),
                              static_cast<unsigned long long>(per_bit));
    }
}

void Pr31x00UartRxDma::SetLine(const LineTiming& timing) {
    std::lock_guard<std::mutex> lk(mu_);
    const LineTiming old = timing_;
    timing_ = timing;
    if (!busy_) return;
    if (old.uart_clocks_per_bit != timing.uart_clocks_per_bit ||
        old.frame_bits != timing.frame_bits || old.transfer_bits != timing.transfer_bits) {
        emu_.Get<Fatal>().Die("Pr31x00UartRxDma %s: the baud divisor or the character framing changed "
                              "while a received character was on the line (%llu -> %llu UART clocks "
                              "per bit, frame %u -> %u bits)", source_,
                              static_cast<unsigned long long>(old.uart_clocks_per_bit),
                              static_cast<unsigned long long>(timing.uart_clocks_per_bit),
                              old.frame_bits, timing.frame_bits);
    }
    ClockRunLocked(clock_->Cycles());
}

void Pr31x00UartRxDma::ClockRunLocked(uint64_t now) {
    if (clocked_) {
        held_count_ = bits_.CountAt(now);
        held_phase_ = bits_.PhaseAt(now);
        held_den_   = bits_.PhaseDenominator();
        clocked_    = false;
        clock_->Disarm(event_);
    }
    if (timing_.uart_clock.num == 0u) return;
    SetBitRatioLocked();
    if (!bits_.AnchorAtPhase(now, held_count_, held_phase_, held_den_)) {
        emu_.Get<Fatal>().Die("Pr31x00UartRxDma %s: the bit phase %llu/%llu does not fit the new "
                              "UART clock ratio", source_,
                              static_cast<unsigned long long>(held_phase_),
                              static_cast<unsigned long long>(held_den_));
    }
    clocked_ = true;
    ArmLocked(now);
}

void Pr31x00UartRxDma::StartRunLocked(uint64_t now) {
    busy_       = true;
    clocked_    = false;
    held_count_ = 0u;
    held_phase_ = 0u;
    held_den_   = 1u;
    next_bit_   = timing_.transfer_bits;
    ClockRunLocked(now);
}

void Pr31x00UartRxDma::StopRunLocked() {
    busy_    = false;
    clocked_ = false;
    clock_->Disarm(event_);
}

bool Pr31x00UartRxDma::ReachedLocked(uint64_t now) const {
    return static_cast<int32_t>(bits_.CountAt(now) - next_bit_) >= 0;
}

void Pr31x00UartRxDma::ArmLocked(uint64_t now) {
    clock_->Arm(event_, ReachedLocked(now) ? now : bits_.NextMatchCycle(next_bit_, now));
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
        if (wire_pos_ >= wire_.size()) {
            wire_.clear();
            wire_pos_ = 0;
        }
        wire_.insert(wire_.end(), data, data + n);
    }
    host_requests_->Request();
}

void Pr31x00UartRxDma::OnHostRequest() {
    std::lock_guard<std::mutex> lk(mu_);
    if (!armed_ || busy_ || wire_pos_ >= wire_.size()) return;
    StartRunLocked(clock_->Cycles());
}

/* §16.4 p16-9: each character is transferred toward the Receive Holding Register as its
   stop bit is clocked in, which asserts UARTnRXINT. */
void Pr31x00UartRxDma::OnCharEvent() {
    RxInts ints;
    bool   idle = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (!busy_ || !clocked_) return;
        const uint64_t now = clock_->Cycles();
        auto&          mem = emu_.Get<EmulatedMemory>();
        while (wire_pos_ < wire_.size() && ReachedLocked(now)) {
            mem.WriteByte(buffer_pa_ + count_, wire_[wire_pos_++]);
            ++count_;
            if (count_ == length_ / 2u) ints.dma_half = true;
            if (count_ >= length_) {
                ints.dma_full = true;
                count_        = 0;
            }
            ints.rx = true;
            next_bit_ += timing_.frame_bits;
        }
        if (wire_pos_ >= wire_.size()) {
            wire_.clear();
            wire_pos_ = 0;
            StopRunLocked();
            idle = true;
        } else {
            ArmLocked(now);
        }
    }
    if (ints.rx && raise_ints_) raise_ints_(ints);
    if (idle && on_line_idle_) on_line_idle_();
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
    StopRunLocked();
}
