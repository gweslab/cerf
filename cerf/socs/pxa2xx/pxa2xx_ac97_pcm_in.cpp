#include "pxa2xx_ac97_pcm_in.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../peripherals/ac97_codec.h"

namespace {

/* Intel PXA255 Developer's Manual Table 5-5 (page 5-13): AC97 audio receive FIFO 0x4050_0040 on DRCMR
   0x4000_012c. */
constexpr uint32_t kPcdr      = 0x40500040u;
constexpr uint32_t kRequestRx = 11u;

}  // namespace

uint32_t Pxa2xxAc97PcmIn::FifoPa() const { return kPcdr; }
uint32_t Pxa2xxAc97PcmIn::Request() const { return kRequestRx; }

uint16_t Pxa2xxAc97PcmIn::SlotValue(uint64_t n) {
    emu_.Get<Fatal>().Die("Pxa2xxAc97PcmIn: value of PCM in slot %llu requested from a FIFO that keeps none",
                          static_cast<unsigned long long>(n));
}

/* AC '97 Component Specification Revision 2.1 Appendix A.3.1 (page 63): "For variable sample rate
   input, the tag bit for each input slot indicates whether valid data is present or not." */
uint32_t Pxa2xxAc97PcmIn::Rate() { return codec_->AdcPowered() ? codec_->AdcRateHz() : 0u; }

void Pxa2xxAc97PcmIn::OnRun() { law_.Reset(0u, Rate()); }

void Pxa2xxAc97PcmIn::OnWrite(uint64_t next_frame) {
    const uint32_t rate = Rate();
    if (rate != law_.RateAt(next_frame)) {
        LOG(SocIis, "AC'97 PCM in %u Hz from frame %llu\n", rate, static_cast<unsigned long long>(next_frame));
    }
    law_.Change(next_frame, rate);
}

void Pxa2xxAc97PcmIn::Save(StateWriter& w) {
    Pxa2xxAc97InFifo::Save(w);
    law_.Save(w, "pcm_in");
}

void Pxa2xxAc97PcmIn::Restore(StateReader& r) {
    Pxa2xxAc97InFifo::Restore(r);
    law_.Restore(r, "pcm_in");
}

REGISTER_SERVICE(Pxa2xxAc97PcmIn);
