#include "pxa2xx_ac97_modem.h"

#include "../../core/cerf_emulator.h"
#include "../../peripherals/ac97_codec.h"
#include "pxa2xx_dma.h"

namespace {

/* Intel PXA255 Developer's Manual Table 5-5 (page 5-13) and Intel PXA27x Developer's Manual Table 5-10
   (page 5-24): AC97 modem receive and transmit FIFO 0x4050_0140 on DRCMR 0x4000_0124 / 0x4000_0128. */
constexpr uint32_t kModr      = 0x40500140u;
constexpr uint32_t kRequestRx = 9u;
constexpr uint32_t kRequestTx = 10u;

}  // namespace

void Pxa2xxAc97Modem::OnReady() {
    Pxa2xxAc97InFifo::OnReady();
    dma_->RegisterUnmodelledRequest(kRequestTx, "AC'97 modem out");
}

uint32_t Pxa2xxAc97Modem::FifoPa() const { return kModr; }
uint32_t Pxa2xxAc97Modem::Request() const { return kRequestRx; }

uint64_t Pxa2xxAc97Modem::Count(uint64_t frames) const { return codec_->SlotWordsBefore(frames); }

bool Pxa2xxAc97Modem::FrameOfSlot(uint64_t slot, uint64_t& frame) const {
    return codec_->FrameOfSlotWord(slot, frame);
}

void Pxa2xxAc97Modem::Prune(uint64_t settled) { codec_->PruneSlotWords(settled); }

uint16_t Pxa2xxAc97Modem::SlotValue(uint64_t n) { return codec_->SlotWord(n); }

REGISTER_SERVICE(Pxa2xxAc97Modem);
