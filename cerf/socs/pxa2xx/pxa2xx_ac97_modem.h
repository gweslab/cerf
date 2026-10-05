#pragma once

#include "pxa2xx_ac97_in_fifo.h"
#include "pxa2xx_slot_source.h"

#include <cstdint>

class Pxa2xxAc97Modem : public Pxa2xxAc97InFifo, public Pxa2xxSlotSource {
public:
    using Pxa2xxAc97InFifo::Pxa2xxAc97InFifo;

    void OnReady() override;

    uint64_t Count(uint64_t frames) const override;
    bool     FrameOfSlot(uint64_t slot, uint64_t& frame) const override;
    void     Prune(uint64_t settled) override;

protected:
    uint32_t          FifoPa() const override;
    uint32_t          Request() const override;
    const char*       NoCodecName() const override { return "AC'97 modem in with no AC'97 codec"; }
    const char*       KeyPrefix() const override { return "modem_in"; }
    Pxa2xxSlotSource& Source() override { return *this; }
    bool              KeepsValues() const override { return true; }
    uint16_t          SlotValue(uint64_t n) override;
    void              OnRun() override {}
    void              OnWrite(uint64_t) override {}
};
