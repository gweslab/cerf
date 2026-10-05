#include "pxa255_i2s_stream.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/audio_activity_widget.h"
#include "../../state/state_stream.h"
#include "../pxa2xx/pxa2xx_dma.h"
#include "pxa255_clock_manager.h"
#include "pxa255_id.h"

namespace {

/* Intel PXA255 Developer's Manual Table 14-3 (page 14-9) SACR0 reset 0x7700; Table 14-6 (page 14-11)
   SACR1: DREC 3, DRPL 4; Table 14-8 (page 14-13): SADIV reset 0x1A. */
constexpr uint32_t kSacr0Reset = 0x7700u;
constexpr uint32_t kSacr1Drec = 1u << 3, kSacr1Drpl = 1u << 4;
constexpr uint32_t kSacr1Defined = 0x39u;
constexpr uint32_t kSadivReset = 0x1Au;
/* Intel PXA255 Developer's Manual Table 14-2 (page 14-6): SYSCLK = PLL / SADIV (12.288 MHz at 0x0C),
   BITCLK = SYSCLK / 4, SYNC = BITCLK / 64. */
constexpr uint64_t kPllHz        = 147456000u;
constexpr uint64_t kSysclkPerBit = 4u;
constexpr uint64_t kBitsPerFrame = 64u;
/* Intel PXA255 Developer's Manual section 14.6.1 (page 14-8): "It takes four BITCLK cycles and four
   internal clock cycles before SACR0[ENB] is conveyed to the slower BITCLK domain"; section 14.6.2
   (page 14-10) says the same of DRPL, DREC and AMSL. */
constexpr uint64_t kSyncBits = 4u;
/* Intel PXA255 Developer's Manual Table 5-5 (page 5-13): I2S FIFO 0x4040_0080, receive on DRCMR
   0x4000_0108, transmit on DRCMR 0x4000_010c; section 14.5.1 (page 14-6): "FIFO buffers are 16
   levels deep and 32 bits wide". */
constexpr uint32_t kSadrPa = 0x40400080u;
constexpr uint32_t kRequestRx = 2u, kRequestTx = 3u;
constexpr uint32_t kFifoDepth = 16u;
constexpr uint16_t kChannels = 2u, kBits = 16u;
/* Intel PXA255 Developer's Manual Table 3-21 (page 3-37): CKEN8 "I2S Unit Clock Enable"; section 3.3.6
   (page 3-6): "When a module's clock is disabled, the registers in that module are still readable and
   writable." */
constexpr uint32_t kCkenI2s = 8u;

uint64_t FramesStarted(uint64_t bits) { return bits < kSyncBits ? 0u : (bits - kSyncBits) / kBitsPerFrame + 1u; }
uint64_t FramesEnded(uint64_t bits) { return bits < kSyncBits ? 0u : (bits - kSyncBits) / kBitsPerFrame; }
uint64_t FrameStartBit(uint64_t frame) { return kSyncBits + frame * kBitsPerFrame; }

}  // namespace

bool Pxa255I2sStream::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Pxa255;
}

void Pxa255I2sStream::OnReady() {
    clock_ = &emu_.Get<GuestCycleClock>();
    mem_   = &emu_.Get<EmulatedMemory>();
    dma_   = &emu_.Get<Pxa2xxDma>();
    clocks_ = &emu_.Get<Pxa255ClockManager>();
    clocks_->RegisterClockEnableListener([this](uint32_t) { OnUnitClock(); });
    dma_->RegisterPort(kRequestTx, &tx_port_);
    dma_->RegisterPort(kRequestRx, &rx_port_);
    clock_->RegisterRateListener([this] { OnCpuRate(); });
    sacr0_ = kSacr0Reset;
    sadiv_ = kSadivReset;
    tx_.Configure(kFifoDepth, TxThreshold(), 1u);
    rx_.Configure(kFifoDepth, RxFreeThreshold(), 1u);
    rx_.Restore(kFifoDepth, 0u);
    host_.Start("Pxa255I2s", 0u, kChannels, kBits, true);
    emu_.Get<AudioActivityWidget>().NotePresent();
}

void Pxa255I2sStream::OnShutdown() { host_.Stop(); }

uint32_t Pxa255I2sStream::Replay() const { return (sacr1_ & kSacr1Drpl) == 0u ? 1u : 0u; }
uint32_t Pxa255I2sStream::Record() const { return (sacr1_ & kSacr1Drec) == 0u ? 1u : 0u; }

GuestCycleClock::Rate Pxa255I2sStream::BitRate() const {
    return GuestCycleClock::Rate{kPllHz, static_cast<uint64_t>(sadiv_) * kSysclkPerBit};
}

/* Intel PXA255 Developer's Manual Table 14-4 (page 14-10), EFWR 0: "I2SLINK reads from the Transmit
   FIFO and writes to the Receive FIFO"; Table 14-7 (page 14-12) TUR "I2S attempted data read from an
   empty Transmit FIFO", ROR "I2S attempted data write to full Receive FIFO". */
void Pxa255I2sStream::Settle(uint64_t now) {
    if (!running_) return;
    const uint64_t bits    = bits_.TicksAt(now);
    const uint64_t started = FramesStarted(bits);
    const uint64_t ended   = FramesEnded(bits);
    if (tx_reset_pending_ && tx_reset_frame_ < started) {
        TakeTo(tx_reset_frame_);
        tx_.Clear();
        tx_reset_pending_ = false;
    }
    TakeTo(started);
    if (rx_reset_pending_ && rx_reset_frame_ <= ended) {
        PushTo(rx_reset_frame_);
        rx_.Restore(kFifoDepth, rx_.Moved());
        rx_reset_pending_ = false;
    }
    PushTo(ended);
}

void Pxa255I2sStream::TakeTo(uint64_t frames) {
    if (frames <= out_frames_) return;
    tx_.Take(out_law_.Count(frames) - out_law_.Count(out_frames_));
    out_frames_ = frames;
    out_law_.Prune(frames);
}

void Pxa255I2sStream::PushTo(uint64_t frames) {
    if (frames <= in_frames_) return;
    rx_.Take(in_law_.Count(frames) - in_law_.Count(in_frames_));
    in_frames_ = frames;
    in_law_.Prune(frames);
}

bool Pxa255I2sStream::TxCycleOfMoved(uint64_t words, uint64_t& cycle) {
    uint64_t n = 0;
    if (!tx_.TakesToMove(words, n)) return false;
    if (n == 0u) {
        cycle = clock_->Cycles();
        return true;
    }
    uint64_t frame = 0;
    if (!running_ || !out_law_.FrameOfSlot(out_law_.Count(out_frames_) + n, frame)) return false;
    cycle = bits_.CycleOfTick(FrameStartBit(frame));
    return true;
}

bool Pxa255I2sStream::RxCycleOfMoved(uint64_t words, uint64_t& cycle) {
    uint64_t m = 0;
    if (!rx_.TakesToMove(words, m)) return false;
    if (m == 0u) {
        cycle = clock_->Cycles();
        return true;
    }
    uint64_t frame = 0;
    if (!running_ || !in_law_.FrameOfSlot(in_law_.Count(in_frames_) + m, frame)) return false;
    cycle = bits_.CycleOfTick(FrameStartBit(frame + 1u));
    return true;
}

uint32_t Pxa255I2sStream::Port::FifoAddress() const { return kSadrPa; }

bool Pxa255I2sStream::Port::RequestAsserted() const {
    const DmaBurstFifo& fifo = receive_ ? i2s_.rx_ : i2s_.tx_;
    const bool          off  = (i2s_.sacr1_ & (receive_ ? kSacr1Drec : kSacr1Drpl)) != 0u;
    return i2s_.running_ && !off && fifo.Level() <= fifo.Threshold();
}

/* Intel PXA255 Developer's Manual section 14.3.2 (page 14-4) DRPL: "Transmit DMA requests are
   disabled"; section 14.3.3 (page 14-5) DREC: "Receive DMA requests are disabled"; Table 14-5
   (page 14-10): TFTH max 14 / 12 / 8 and RFTH min 1 / 3 / 7 for 2 / 4 / 8-entry transfers. */
void Pxa255I2sStream::Port::SetService(uint64_t now, uint32_t burst_words, uint64_t supply_words) {
    i2s_.Settle(now);
    const bool     off    = (i2s_.sacr1_ & (receive_ ? kSacr1Drec : kSacr1Drpl)) != 0u;
    const uint64_t supply = i2s_.running_ && !off ? supply_words : 0u;
    if (supply != 0u && (receive_ ? i2s_.Rfth() + 1u < burst_words
                                  : i2s_.TxThreshold() + burst_words > kFifoDepth)) {
        i2s_.emu_.Get<Fatal>().Die("Pxa255I2s: SACR0 0x%08X with %u-entry DMA transfers can over-run the "
                                   "transmit FIFO or under-run the receive FIFO; not modelled",
                                   i2s_.sacr0_, burst_words);
    }
    DmaBurstFifo& fifo = receive_ ? i2s_.rx_ : i2s_.tx_;
    fifo.Configure(kFifoDepth, receive_ ? i2s_.RxFreeThreshold() : i2s_.TxThreshold(), burst_words);
    fifo.SetSupply(supply);
    fifo.Refill();
}

void Pxa255I2sStream::Port::TransmitBlock(uint32_t pa, uint32_t bytes) {
    i2s_.block_.resize(bytes);
    i2s_.mem_->CopyOut(pa, i2s_.block_.data(), bytes);
    i2s_.QueueHost(i2s_.block_.data(), bytes);
}

void Pxa255I2sStream::Port::ReceiveBlock(uint32_t pa, uint32_t bytes) {
    i2s_.block_.assign(bytes, 0u);
    i2s_.mem_->CopyIn(pa, i2s_.block_.data(), bytes);
}

void Pxa255I2sStream::Port::Stopped(uint64_t now, bool) {
    i2s_.Settle(now);
    if (receive_ || !i2s_.host_active_) return;
    i2s_.host_.FinishAudioOut();
    i2s_.host_active_ = false;
}

void Pxa255I2sStream::QueueHost(const void* bytes, uint32_t length) {
    const uint64_t den  = static_cast<uint64_t>(sadiv_) * kSysclkPerBit * kBitsPerFrame;
    const uint32_t rate = static_cast<uint32_t>((kPllHz + den / 2u) / den);
    if (rate != host_rate_) {
        host_rate_ = rate;
        host_.SetFormat(rate, kChannels, kBits);
    }
    if (!host_active_) {
        host_.BeginAudioOut({});
        host_active_ = true;
    }
    host_.QueueOutput(bytes, length);
    emu_.Get<AudioActivityWidget>().MarkTx();
}

/* Intel PXA255 Developer's Manual section 14.6.1 (page 14-8): "Setting ENB to one ... enables DMA
   requests"; Table 14-3 (page 14-9): "Transmit DMA Request asserted whenever the Transmit FIFO has <
   (TFTH+1) entries", "Receive DMA Request asserted whenever the Receive FIFO has >= (RFTH+1) entries". */
void Pxa255I2sStream::Enable(uint64_t now, uint32_t sacr0) {
    sacr0_       = sacr0;
    enabled_     = true;
    held_        = RatedTickCount::Position{};
    gated_sacr1_ = sacr1_;
    out_frames_  = 0u;
    in_frames_   = 0u;
    out_law_.Reset(0u, Replay());
    in_law_.Reset(0u, Record());
    if (UnitClockOn()) Resume(now);
    dma_->OnPortChange();
}

bool Pxa255I2sStream::UnitClockOn() const { return clocks_->ClockEnabled(kCkenI2s); }

void Pxa255I2sStream::OnUnitClock() {
    if (!enabled_ || UnitClockOn() == running_) return;
    const uint64_t now = clock_->Cycles();
    if (running_) {
        Gate(now);
    } else {
        Resume(now);
    }
    dma_->OnPortChange();
}

void Pxa255I2sStream::Resume(uint64_t now) {
    if (!bits_.SetRate(clock_->ClockRate(), BitRate()) || !bits_.PlaceAt(now, held_)) {
        emu_.Get<Fatal>().Die("Pxa255I2s: the I2S bit clock at SADIV 0x%02X does not fit the core "
                              "clock ratio", sadiv_);
    }
    running_ = true;
    ApplySacr1(now, gated_sacr1_);
}

void Pxa255I2sStream::Gate(uint64_t now) {
    Settle(now);
    held_        = bits_.PositionAt(now);
    gated_sacr1_ = sacr1_;
    running_     = false;
}

void Pxa255I2sStream::WriteSacr1(uint64_t now, uint32_t value) {
    Settle(now);
    const uint32_t old = sacr1_;
    sacr1_ = value & kSacr1Defined;
    if (running_) ApplySacr1(now, old);
    dma_->OnPortChange();
}

/* Intel PXA255 Developer's Manual section 14.6.2 (page 14-10): if DRPL / DREC "are modified at a rate faster
   than (4 BITCLK + 4 internal clock) cycles, the last updated value in this time frame is stored in a temporary
   register and is transferred to the BITCLK domain". */
void Pxa255I2sStream::ApplySacr1(uint64_t now, uint32_t old) {
    const uint64_t bits  = bits_.TicksAt(now);
    const uint64_t first = (bits + kBitsPerFrame - 1u) / kBitsPerFrame;
    out_law_.Change(first, Replay());
    in_law_.Change(first, Record());
    ApplyFifoReset(sacr1_ & kSacr1Drpl, old & kSacr1Drpl, bits, first, tx_reset_pending_, tx_reset_frame_,
                   tx_assert_bit_);
    ApplyFifoReset(sacr1_ & kSacr1Drec, old & kSacr1Drec, bits, first, rx_reset_pending_, rx_reset_frame_,
                   rx_assert_bit_);
}

/* Intel PXA255 Developer's Manual section 14.3.2 (page 14-4): "Asserting the DRPL bit in SACR1 has the following
   effects", among them "Transmit FIFO pointers are reset to zero". */
void Pxa255I2sStream::ApplyFifoReset(uint32_t now_set, uint32_t was_set, uint64_t bits, uint64_t first,
                                     bool& pending, uint64_t& frame, uint64_t& assert_bit) {
    if (now_set != 0u && was_set == 0u && !pending) {
        pending    = true;
        frame      = first;
        assert_bit = bits;
    } else if (now_set == 0u && was_set != 0u && pending && bits < assert_bit + kSyncBits) {
        pending = false;
    }
}

void Pxa255I2sStream::WriteData(uint64_t now, uint32_t value) {
    if (enabled_ && !running_) {
        emu_.Get<Fatal>().Die("Pxa255I2s: SADR write 0x%08X with SACR0 ENB set and CKEN8 gating the I2S unit "
                              "clock; not modelled", value);
    }
    Settle(now);
    if (tx_.Level() >= kFifoDepth) {
        emu_.Get<Fatal>().Die("Pxa255I2s: SADR write 0x%08X into a full transmit FIFO; not modelled",
                              value);
    }
    tx_.Put();
    QueueHost(&value, sizeof(value));
}

/* Intel PXA255 Developer's Manual section 14.6.1 (page 14-8): with ENB clear "any read accesses to the
   Data Register (SADR), by the processor, or by the DMA controller is returned with zeros"; section
   14.3.3 (page 14-5) DREC: "Any read operations by the DMA/CPU are returned with zeros". */
uint32_t Pxa255I2sStream::ReadData(uint64_t now) {
    if (!enabled_ || (sacr1_ & kSacr1Drec) != 0u) return 0u;
    if (!running_) {
        emu_.Get<Fatal>().Die("Pxa255I2s: SADR read with SACR0 ENB set and CKEN8 gating the I2S unit clock; "
                              "not modelled");
    }
    Settle(now);
    if (rx_.Level() < kFifoDepth) rx_.Put();
    return 0u;
}

void Pxa255I2sStream::OnCpuRate() {
    if (!running_) return;
    const uint64_t now = clock_->Cycles();
    Settle(now);
    if (!bits_.Rescale(now, clock_->ClockRate(), BitRate())) {
        emu_.Get<Fatal>().Die("Pxa255I2s: the I2S bit clock at SADIV 0x%02X does not fit the core "
                              "clock ratio", sadiv_);
    }
    dma_->OnPortChange();
}

void Pxa255I2sStream::ResetLine() {
    Settle(clock_->Cycles());
    enabled_     = false;
    running_     = false;
    held_        = RatedTickCount::Position{};
    gated_sacr1_ = 0u;
    out_frames_ = 0u;
    in_frames_  = 0u;
    tx_reset_pending_ = rx_reset_pending_ = false;
    tx_assert_bit_ = rx_assert_bit_ = 0u;
    sacr0_      = kSacr0Reset;
    sacr1_      = 0u;
    sadiv_      = kSadivReset;
    tx_.Clear();
    rx_.Restore(kFifoDepth, rx_.Moved());
    host_.StopAudioOut();
    host_active_ = false;
    host_rate_   = 0u;
}

void Pxa255I2sStream::Save(StateWriter& w) {
    const uint64_t now = clock_->Cycles();
    Settle(now);
    const RatedTickCount::Position pos = running_ ? bits_.PositionAt(now) : held_;
    w.Write("sacr0", sacr0_);
    w.Write("sacr1", sacr1_);
    w.Write("sadiv", sadiv_);
    w.Write<uint8_t>("i2s_enabled", enabled_ ? 1u : 0u);
    w.Write<uint8_t>("i2s_running", running_ ? 1u : 0u);
    w.Write<uint32_t>("i2s_gated_sacr1", gated_sacr1_);
    w.Write<uint64_t>("i2s_bits_ticks", pos.ticks);
    w.Write<uint64_t>("i2s_bits_phase", pos.phase);
    w.Write<uint64_t>("i2s_bits_phase_den", pos.phase_den);
    w.Write<uint64_t>("i2s_out_frames", out_frames_);
    w.Write<uint64_t>("i2s_in_frames", in_frames_);
    w.Write<uint8_t>("i2s_tx_reset_pending", tx_reset_pending_ ? 1u : 0u);
    w.Write<uint64_t>("i2s_tx_reset_frame", tx_reset_frame_);
    w.Write<uint8_t>("i2s_rx_reset_pending", rx_reset_pending_ ? 1u : 0u);
    w.Write<uint64_t>("i2s_rx_reset_frame", rx_reset_frame_);
    w.Write<uint64_t>("i2s_tx_assert_bit", tx_assert_bit_);
    w.Write<uint64_t>("i2s_rx_assert_bit", rx_assert_bit_);
    w.Write<uint32_t>("i2s_tx_level", tx_.Level());
    w.Write<uint64_t>("i2s_tx_moved", tx_.Moved());
    w.Write<uint32_t>("i2s_rx_free", rx_.Level());
    w.Write<uint64_t>("i2s_rx_moved", rx_.Moved());
    out_law_.Save(w, "i2s_out");
    in_law_.Save(w, "i2s_in");
}

void Pxa255I2sStream::Restore(StateReader& r) {
    uint8_t  enabled = 0, running = 0, tx_reset_pending = 0, rx_reset_pending = 0;
    uint32_t tx_level = 0, rx_free = 0;
    uint64_t tx_moved = 0, rx_moved = 0;
    RatedTickCount::Position pos;
    r.Read("sacr0", sacr0_);
    r.Read("sacr1", sacr1_);
    r.Read("sadiv", sadiv_);
    r.Read("i2s_enabled", enabled);
    r.Read("i2s_running", running);
    r.Read("i2s_gated_sacr1", gated_sacr1_);
    r.Read("i2s_bits_ticks", pos.ticks);
    r.Read("i2s_bits_phase", pos.phase);
    r.Read("i2s_bits_phase_den", pos.phase_den);
    r.Read("i2s_out_frames", out_frames_);
    r.Read("i2s_in_frames", in_frames_);
    r.Read("i2s_tx_reset_pending", tx_reset_pending);
    r.Read("i2s_tx_reset_frame", tx_reset_frame_);
    r.Read("i2s_rx_reset_pending", rx_reset_pending);
    r.Read("i2s_rx_reset_frame", rx_reset_frame_);
    r.Read("i2s_tx_assert_bit", tx_assert_bit_);
    r.Read("i2s_rx_assert_bit", rx_assert_bit_);
    r.Read("i2s_tx_level", tx_level);
    r.Read("i2s_tx_moved", tx_moved);
    r.Read("i2s_rx_free", rx_free);
    r.Read("i2s_rx_moved", rx_moved);
    out_law_.Restore(r, "i2s_out");
    in_law_.Restore(r, "i2s_in");
    tx_reset_pending_ = tx_reset_pending != 0u;
    rx_reset_pending_ = rx_reset_pending != 0u;
    tx_.Restore(tx_level, tx_moved);
    rx_.Restore(rx_free, rx_moved);
    tx_.SetSupply(0u);
    rx_.SetSupply(0u);
    enabled_ = enabled != 0u;
    running_ = running != 0u;
    held_    = running_ ? RatedTickCount::Position{} : pos;
    host_.StopAudioOut();
    host_active_ = false;
    host_rate_   = 0u;
    if (!running_) return;
    if (!bits_.SetRate(clock_->ClockRate(), BitRate()) || !bits_.PlaceAt(clock_->Cycles(), pos)) {
        r.Reject("Pxa255I2s: the restored I2S bit clock at %llu phase %llu/%llu does not fit the current "
                 "core ratio", static_cast<unsigned long long>(pos.ticks),
                 static_cast<unsigned long long>(pos.phase),
                 static_cast<unsigned long long>(pos.phase_den));
    }
}

REGISTER_SERVICE(Pxa255I2sStream);
