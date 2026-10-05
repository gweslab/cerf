#include "pxa2xx_ac97_pcm.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/audio_activity_widget.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/ac97_codec.h"
#include "../../state/state_stream.h"
#include "../pxa255/pxa255_id.h"
#include "../pxa27x/pxa270_id.h"
#include "pxa2xx_dma.h"

#include <algorithm>

namespace {

/* Intel PXA27x Developer's Manual section 13.6.5 (page 13-18): sixteen-entry FIFOs; "A receive
   FIFO triggers a DMA request when the FIFO has eight or more entries. A transmit FIFO triggers
   a DMA request when it holds less than eight entries." */
constexpr uint32_t kFifoDepth   = 16u;
constexpr uint32_t kTxThreshold = 7u;
constexpr uint32_t kHalfFull    = 8u;
/* Intel PXA255 Developer's Manual Table 5-5 (page 5-13): AC97 audio transmit FIFO 0x4050_0040 on DRCMR
   0x4000_0130, microphone on DRCMR 0x4000_0120. */
constexpr uint32_t kPcdr       = 0x40500040u;
constexpr uint32_t kRequestMic = 8u;
constexpr uint32_t kRequestTx  = 12u;
constexpr uint16_t kChannels   = 2u;
constexpr uint16_t kBits       = 16u;

}  // namespace

bool Pxa2xxAc97Pcm::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && (bd->GetSocId() == SocId::Pxa255 || bd->GetSocId() == SocId::Pxa270);
}

void Pxa2xxAc97Pcm::OnReady() {
    link_  = &emu_.Get<Pxa2xxAc97Link>();
    codec_ = emu_.TryGet<Ac97Codec>();
    clock_ = &emu_.Get<GuestCycleClock>();
    mem_   = &emu_.Get<EmulatedMemory>();
    dma_   = &emu_.Get<Pxa2xxDma>();
    link_->AddListener(this);
    tx_.Configure(kFifoDepth, kTxThreshold, kHalfFull);
    if (codec_ != nullptr) {
        dma_->RegisterPort(kRequestTx, &out_port_);
    } else {
        dma_->RegisterUnmodelledRequest(kRequestTx, "AC'97 PCM out with no AC'97 codec");
    }
    dma_->RegisterUnmodelledRequest(kRequestMic, "AC'97 microphone in");
    host_.Start("Pxa2xxAc97Pcm", 0u, kChannels, kBits, true);
    emu_.Get<AudioActivityWidget>().NotePresent();
}

void Pxa2xxAc97Pcm::OnShutdown() { host_.Stop(); }

void Pxa2xxAc97Pcm::Settle(uint64_t now) {
    link_->Settle(now);
    SettleTo(now);
}

/* Intel PXA27x Developer's Manual section 13.6.5.1 (page 13-18): "During transmit-underrun
   conditions, the last valid sample is continuously sent out". */
void Pxa2xxAc97Pcm::SettleTo(uint64_t now) {
    if (!link_->Running() || !primed_) return;
    const uint64_t started = link_->FrameIndexAt(now) + 1u;
    const uint64_t from    = std::max(out_frames_, prime_frame_);
    if (started <= from) return;
    const uint64_t takes = out_law_.Count(started) - out_law_.Count(from);
    if (tx_.Take(takes) != 0u) out_error_ = true;
    out_frames_ = started;
    out_law_.Prune(started);
}

/* Intel PXA255 Developer's Manual section 13.6.1 (page 13-15): "The ACUNIT continues to transmit
   zeroes until the transmit FIFO is half full. When it is half full, valid transmit FIFO data is
   sent across the AC-link." */
void Pxa2xxAc97Pcm::CheckPrimed(uint64_t now) {
    if (primed_ || tx_.Level() < kHalfFull) return;
    primed_      = true;
    prime_frame_ = link_->Running() ? link_->FrameIndexAt(now) + 1u : 0u;
    LOG(SocIis, "AC'97 PCM out primed from frame %llu (link %s)\n",
        static_cast<unsigned long long>(prime_frame_), link_->Running() ? "running" : "stopped");
}

void Pxa2xxAc97Pcm::RequireCodec(const char* access) {
    if (codec_ != nullptr) return;
    emu_.Get<Fatal>().Die("Pxa2xxAc97Pcm: %s with no AC'97 codec on this board; not modelled", access);
}

/* AC '97 Component Specification Revision 2.1 Appendix A.3.2 (page 64): SLOTREQ bits "are always
   0" for a fixed-rate mode (VRA=0) or an "inactive (powered down) DAC channel"; Table 34: "0= send
   data". */
uint32_t Pxa2xxAc97Pcm::OutRate() {
    return codec_->DacPowered() ? codec_->DacRateHz() : Pxa2xxAc97Link::kFrameRateHz;
}

void Pxa2xxAc97Pcm::OnLinkRun(uint64_t ) {
    out_frames_  = 0u;
    prime_frame_ = 0u;
    out_law_.Reset(0u, OutRate());
}

void Pxa2xxAc97Pcm::OnLinkStop(uint64_t cycle) { SettleTo(cycle); }

/* Intel PXA27x Developer's Manual section 13.6.2 (page 13-17): ACOFF "discards all remaining data
   in the transmit FIFO and receive FIFO"; Table 13-8 (page 13-22) nCRST: "All data in the
   controller and the Codec is lost." */
void Pxa2xxAc97Pcm::OnFifoReset(uint64_t cycle, bool cold) {
    SettleTo(cycle);
    tx_.Clear();
    tx_.SetSupply(0u);
    primed_ = false;
    if (cold) out_error_ = false;
}

void Pxa2xxAc97Pcm::OnCodecWrite(uint64_t cycle) {
    SettleTo(cycle);
    const uint64_t next = link_->FrameIndexAt(cycle) + 1u;
    const uint32_t out  = OutRate();
    if (out != out_law_.RateAt(next)) {
        LOG(SocIis, "AC'97 PCM out %u Hz from frame %llu\n", out, static_cast<unsigned long long>(next));
    }
    out_law_.Change(next, out);
}

void Pxa2xxAc97Pcm::OnLinkEvent() { dma_->OnPortChange(); }

bool Pxa2xxAc97Pcm::TxRequest() const { return link_->RequestsEnabled() && tx_.Level() <= tx_.Threshold(); }

/* Intel PXA27x Developer's Manual Table 13-12 (page 13-28) POSR: FIFOE "Set when a FIFO error
   occurs", FSR "FIFO needs servicing"; Table 13-13 (page 13-29) PCMISR adds EOC. */
uint32_t Pxa2xxAc97Pcm::OutStatus(uint64_t now) {
    Settle(now);
    uint32_t s = out_error_ ? kFifoe : 0u;
    if (TxRequest()) s |= kFsr;
    return s;
}

void Pxa2xxAc97Pcm::ClearOutStatus(uint64_t now, uint32_t mask) {
    Settle(now);
    if ((mask & kFifoe) != 0u) out_error_ = false;
}

/* Intel PXA27x Developer's Manual Table 13-12 (page 13-28) FIFOE: "Transmit FIFO overrun occurs.
   Data in the transmit FIFO is preserved ... programmed I/O tries to update the transmit FIFO
   when it is already full". */
void Pxa2xxAc97Pcm::WriteData(uint64_t now, uint32_t value) {
    RequireCodec("PCDR write");
    Settle(now);
    if (tx_.Level() >= kFifoDepth) {
        out_error_ = true;
        return;
    }
    tx_.Put();
    CheckPrimed(now);
    QueueHost(&value, sizeof(value));
}

void Pxa2xxAc97Pcm::QueueHost(const void* bytes, uint32_t length) {
    const uint32_t rate = codec_->DacRateHz();
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

bool Pxa2xxAc97Pcm::TxCycleOfMoved(uint64_t words, uint64_t& cycle) {
    uint64_t n = 0;
    if (!tx_.TakesToMove(words, n)) return false;
    if (n == 0u) {
        cycle = clock_->Cycles();
        return true;
    }
    if (!link_->Running() || !primed_) return false;
    const uint64_t from  = std::max(out_frames_, prime_frame_);
    uint64_t       frame = 0;
    if (!out_law_.FrameOfSlot(out_law_.Count(from) + n, frame)) return false;
    cycle = link_->CycleOfFrame(frame);
    return true;
}

uint32_t Pxa2xxAc97Pcm::OutPort::FifoAddress() const { return kPcdr; }

void Pxa2xxAc97Pcm::OutPort::SetService(uint64_t now, uint32_t burst_words, uint64_t supply_words) {
    pcm_.Settle(now);
    const uint64_t supply = pcm_.link_->RequestsEnabled() ? supply_words : 0u;
    pcm_.tx_.Configure(kFifoDepth, kTxThreshold, burst_words);
    pcm_.tx_.SetSupply(supply);
    pcm_.tx_.Refill();
    pcm_.CheckPrimed(now);
}

void Pxa2xxAc97Pcm::OutPort::TransmitBlock(uint32_t pa, uint32_t bytes) {
    pcm_.block_.resize(bytes);
    pcm_.mem_->CopyOut(pa, pcm_.block_.data(), bytes);
    pcm_.QueueHost(pcm_.block_.data(), bytes);
}

void Pxa2xxAc97Pcm::OutPort::ReceiveBlock(uint32_t pa, uint32_t bytes) {
    pcm_.emu_.Get<Fatal>().Die("Pxa2xxAc97Pcm: receive block of %u bytes at 0x%08X on the PCM out FIFO",
                               bytes, pa);
}

void Pxa2xxAc97Pcm::OutPort::Stopped(uint64_t now, bool) {
    pcm_.Settle(now);
    if (!pcm_.host_active_) return;
    pcm_.host_.FinishAudioOut();
    pcm_.host_active_ = false;
}

void Pxa2xxAc97Pcm::Save(StateWriter& w) {
    Settle(clock_->Cycles());
    w.Write<uint32_t>("pcm_tx_level", tx_.Level());
    w.Write<uint64_t>("pcm_tx_moved", tx_.Moved());
    w.Write<uint8_t>("pcm_primed", primed_ ? 1u : 0u);
    w.Write<uint64_t>("pcm_prime_frame", prime_frame_);
    w.Write<uint64_t>("pcm_out_frames", out_frames_);
    w.Write<uint8_t>("pcm_out_error", out_error_ ? 1u : 0u);
    out_law_.Save(w, "pcm_out");
}

void Pxa2xxAc97Pcm::Restore(StateReader& r) {
    uint32_t tx_level = 0;
    uint64_t tx_moved = 0;
    uint8_t  primed = 0, out_error = 0;
    r.Read("pcm_tx_level", tx_level);
    r.Read("pcm_tx_moved", tx_moved);
    r.Read("pcm_primed", primed);
    r.Read("pcm_prime_frame", prime_frame_);
    r.Read("pcm_out_frames", out_frames_);
    r.Read("pcm_out_error", out_error);
    out_law_.Restore(r, "pcm_out");
    tx_.Restore(tx_level, tx_moved);
    tx_.SetSupply(0u);
    primed_      = primed != 0u;
    out_error_   = out_error != 0u;
    host_.StopAudioOut();
    host_active_ = false;
    host_rate_   = 0u;
}

REGISTER_SERVICE(Pxa2xxAc97Pcm);
