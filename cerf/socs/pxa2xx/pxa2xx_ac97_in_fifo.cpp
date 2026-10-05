#include "pxa2xx_ac97_in_fifo.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../cpu/emulated_memory.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/ac97_codec.h"
#include "../../state/state_stream.h"
#include "../pxa255/pxa255_id.h"
#include "../pxa27x/pxa270_id.h"
#include "pxa2xx_dma.h"
#include "pxa2xx_slot_source.h"

#include <string>
#include <vector>

namespace {

/* Intel PXA255 Developer's Manual section 13.8.1 (page 13-18): receive FIFOs "with sixteen 32-bit
   entries"; "A receive FIFO triggers a DMA request when the FIFO has eight or more entries"; "During
   receive over-run conditions, data that the CODEC sends is not recorded." */
constexpr uint32_t kDepth         = 16u;
constexpr uint32_t kFreeThreshold = 8u;
constexpr uint32_t kRequestLevel  = 8u;
constexpr uint32_t kWordBytes     = 4u;

}  // namespace

bool Pxa2xxAc97InFifo::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && (bd->GetSocId() == SocId::Pxa255 || bd->GetSocId() == SocId::Pxa270);
}

void Pxa2xxAc97InFifo::OnReady() {
    link_  = &emu_.Get<Pxa2xxAc97Link>();
    codec_ = emu_.TryGet<Ac97Codec>();
    clock_ = &emu_.Get<GuestCycleClock>();
    dma_   = &emu_.Get<Pxa2xxDma>();
    mem_   = &emu_.Get<EmulatedMemory>();
    link_->AddListener(this);
    fifo_.Configure(kDepth, kFreeThreshold, kRequestLevel);
    fifo_.Restore(kDepth, 0u);
    if (codec_ != nullptr) {
        dma_->RegisterPort(Request(), this);
    } else {
        dma_->RegisterUnmodelledRequest(Request(), NoCodecName());
    }
}

void Pxa2xxAc97InFifo::Discard(bool cold) {
    const uint64_t pending = fifo_.Moved() - written_;
    while (held_.size() > pending) held_.pop_back();
    fifo_.Restore(kDepth, fifo_.Moved());
    fifo_.SetSupply(0u);
    dma_serving_ = false;
    if (!cold) return;
    error_ = false;
    eoc_   = false;
}

void Pxa2xxAc97InFifo::SettleTo(uint64_t now) {
    if (!link_->Running()) return;
    const uint64_t ended = link_->FrameIndexAt(now);
    if (ended <= frames_) return;
    Pxa2xxSlotSource& source   = Source();
    const uint64_t    first    = source.Count(frames_);
    const uint64_t    pushes   = source.Count(ended) - first;
    const uint64_t    dropped  = fifo_.Take(pushes);
    const uint64_t    accepted = pushes - dropped;
    if (dropped != 0u) error_ = true;
    if (KeepsValues()) {
        for (uint64_t i = 1u; i <= accepted; ++i) held_.push_back(SlotValue(first + i));
    }
    frames_ = ended;
    source.Prune(ended);
}

void Pxa2xxAc97InFifo::Settle(uint64_t now) {
    link_->Settle(now);
    SettleTo(now);
}

uint32_t Pxa2xxAc97InFifo::Filled() const { return kDepth - fifo_.Level(); }

/* Intel PXA27x Developer's Manual Table 13-22 (page 13-38) FSR: "1 = FIFO needs servicing". */
bool Pxa2xxAc97InFifo::ServiceRequest() const {
    return link_->RequestsEnabled() && fifo_.Level() <= fifo_.Threshold();
}

uint32_t Pxa2xxAc97InFifo::Status(uint64_t now) {
    Settle(now);
    uint32_t s = error_ ? kFifoe : 0u;
    if (eoc_) s |= kEoc;
    if (ServiceRequest()) s |= kFsr;
    return s;
}

/* Intel PXA27x Developer's Manual Table 13-22 (page 13-38) EOC: "This bit can only be cleared by a
   dedicated write of 0b1 to this bit location. Concurrent clearing of multiple bits in this register
   does not clear EOC." */
void Pxa2xxAc97InFifo::ClearStatus(uint64_t now, uint32_t mask) {
    Settle(now);
    if ((mask & kFifoe) != 0u) error_ = false;
    if ((mask & (kFifoe | kEoc)) == kEoc) eoc_ = false;
}

/* Intel PXA27x Developer's Manual Table 13-22 (page 13-38) FIFOE: "Receive FIFO underrun occurs.
   Invalid data is read by the CPU. Pointers do not increment." */
uint16_t Pxa2xxAc97InFifo::ReadData(uint64_t now, const char* reg) {
    if (codec_ == nullptr) {
        emu_.Get<Fatal>().Die("Pxa2xxAc97InFifo: %s read with no AC'97 codec on this board; not modelled", reg);
    }
    Settle(now);
    if (dma_serving_) {
        emu_.Get<Fatal>().Die("Pxa2xxAc97InFifo: %s read by programmed I/O while DMA serves the FIFO; "
                              "not modelled", reg);
    }
    if (Filled() == 0u) {
        error_ = true;
        return 0u;
    }
    fifo_.Put();
    if (!KeepsValues()) return 0u;
    const uint16_t v = held_.front();
    held_.pop_front();
    return v;
}

void Pxa2xxAc97InFifo::SetService(uint64_t now, uint32_t burst_words, uint64_t supply_words) {
    Settle(now);
    const uint64_t supply = link_->RequestsEnabled() ? supply_words : 0u;
    fifo_.Configure(kDepth, kFreeThreshold, burst_words);
    fifo_.SetSupply(supply);
    fifo_.Refill();
    dma_serving_ = supply != 0u;
}

bool Pxa2xxAc97InFifo::CycleOfMoved(uint64_t words, uint64_t& cycle) {
    uint64_t m = 0;
    if (!fifo_.TakesToMove(words, m)) return false;
    if (m == 0u) {
        cycle = clock_->Cycles();
        return true;
    }
    if (!link_->Running()) return false;
    Pxa2xxSlotSource& source = Source();
    uint64_t          frame  = 0;
    if (!source.FrameOfSlot(source.Count(frames_) + m, frame)) return false;
    cycle = link_->CycleOfFrame(frame + 1u);
    return true;
}

void Pxa2xxAc97InFifo::TransmitBlock(uint32_t pa, uint32_t bytes) {
    emu_.Get<Fatal>().Die("Pxa2xxAc97InFifo: transmit block of %u bytes at 0x%08X on a receive FIFO", bytes, pa);
}

void Pxa2xxAc97InFifo::ReceiveBlock(uint32_t pa, uint32_t bytes) {
    const uint32_t        words = (bytes + kWordBytes - 1u) / kWordBytes;
    std::vector<uint32_t> data(words, 0u);
    for (uint32_t i = 0; i < words; ++i) {
        if (!KeepsValues()) continue;
        data[i] = held_.front();
        held_.pop_front();
    }
    written_ += words;
    mem_->CopyIn(pa, data.data(), bytes);
}

/* Intel PXA27x Developer's Manual Table 13-22 (page 13-38) EOC: "Set to 0b1 by AC '97 controller
   hardware when DMA signals an end of descriptor chain (EOC) while reading data from the FIFO." */
void Pxa2xxAc97InFifo::Stopped(uint64_t now, bool end_of_chain) {
    Settle(now);
    dma_serving_ = false;
    if (end_of_chain) eoc_ = true;
}

void Pxa2xxAc97InFifo::OnLinkRun(uint64_t) {
    frames_ = 0u;
    OnRun();
}

void Pxa2xxAc97InFifo::OnLinkStop(uint64_t cycle) { SettleTo(cycle); }

void Pxa2xxAc97InFifo::OnFifoReset(uint64_t cycle, bool cold) {
    SettleTo(cycle);
    Discard(cold);
}

void Pxa2xxAc97InFifo::OnCodecWrite(uint64_t cycle) {
    SettleTo(cycle);
    OnWrite(link_->FrameIndexAt(cycle) + 1u);
}

void Pxa2xxAc97InFifo::OnLinkEvent() {
    Settle(clock_->Cycles());
    dma_->OnPortChange();
}

void Pxa2xxAc97InFifo::Save(StateWriter& w) {
    Settle(clock_->Cycles());
    const std::string p = KeyPrefix();
    w.Write<uint32_t>((p + "_free").c_str(), fifo_.Level());
    w.Write<uint64_t>((p + "_moved").c_str(), fifo_.Moved());
    w.Write<uint64_t>((p + "_frames").c_str(), frames_);
    w.Write<uint64_t>((p + "_written").c_str(), written_);
    w.Write<uint8_t>((p + "_error").c_str(), error_ ? 1u : 0u);
    w.Write<uint8_t>((p + "_eoc").c_str(), eoc_ ? 1u : 0u);
    w.Write<uint32_t>((p + "_held").c_str(), static_cast<uint32_t>(held_.size()));
    for (uint16_t v : held_) w.Write<uint16_t>((p + "_held_value").c_str(), v);
}

void Pxa2xxAc97InFifo::Restore(StateReader& r) {
    const std::string p = KeyPrefix();
    uint32_t free = 0, held = 0;
    uint64_t moved = 0;
    uint8_t  error = 0, eoc = 0;
    r.Read((p + "_free").c_str(), free);
    r.Read((p + "_moved").c_str(), moved);
    r.Read((p + "_frames").c_str(), frames_);
    r.Read((p + "_written").c_str(), written_);
    r.Read((p + "_error").c_str(), error);
    r.Read((p + "_eoc").c_str(), eoc);
    r.Read((p + "_held").c_str(), held);
    held_.assign(held, 0u);
    for (uint16_t& v : held_) r.Read((p + "_held_value").c_str(), v);
    fifo_.Restore(free, moved);
    fifo_.SetSupply(0u);
    dma_serving_ = false;
    error_       = error != 0u;
    eoc_         = eoc != 0u;
}
