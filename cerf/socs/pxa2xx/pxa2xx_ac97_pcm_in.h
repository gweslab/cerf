#pragma once

#include "pxa2xx_ac97_in_fifo.h"
#include "pxa2xx_ac97_link.h"
#include "pxa2xx_frame_slot_law.h"

#include <cstdint>

class Pxa2xxAc97PcmIn : public Pxa2xxAc97InFifo {
public:
    using Pxa2xxAc97InFifo::Pxa2xxAc97InFifo;

    void Save(StateWriter& w) override;
    void Restore(StateReader& r) override;

protected:
    uint32_t          FifoPa() const override;
    uint32_t          Request() const override;
    const char*       NoCodecName() const override { return "AC'97 PCM in with no AC'97 codec"; }
    const char*       KeyPrefix() const override { return "pcm_in"; }
    Pxa2xxSlotSource& Source() override { return law_; }
    bool              KeepsValues() const override { return false; }
    uint16_t          SlotValue(uint64_t n) override;
    void              OnRun() override;
    void              OnWrite(uint64_t next_frame) override;

private:
    uint32_t Rate();

    Pxa2xxFrameSlotLaw law_{Pxa2xxAc97Link::kFrameRateHz};
};
