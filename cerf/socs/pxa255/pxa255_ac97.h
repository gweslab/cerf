#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>

class Ac97Codec;
class GuestCycleClock;
class Pxa255ClockManager;
class Pxa2xxAc97Link;
class Pxa2xxAc97Modem;
class Pxa2xxAc97Pcm;
class Pxa2xxAc97PcmIn;
class Pxa2xxDma;

class Pxa255Ac97 : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x40500000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint16_t ReadHalf (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

private:
    static bool IsRegister(uint32_t off);
    void        OnUnitClock(uint32_t old_cken);
    void        RequireOutOfReset(uint32_t off);
    void        WriteGcr(uint64_t now, uint32_t value);
    void        WriteControl(uint32_t& reg, uint32_t value, const char* name);
    void        ResetLine();

    static constexpr uint32_t kPOCR = 0x00u, kPICR = 0x04u, kMCCR = 0x08u, kGCR = 0x0Cu,
                              kPOSR = 0x10u, kPISR = 0x14u, kGSR = 0x1Cu, kCAR = 0x20u,
                              kPCDR = 0x40u, kMOCR = 0x100u, kMICR = 0x108u, kMISR = 0x118u,
                              kMODR = 0x140u;

    GuestCycleClock*    clock_  = nullptr;
    Pxa255ClockManager* clocks_ = nullptr;
    Pxa2xxAc97Link*  link_  = nullptr;
    Pxa2xxAc97Pcm*   pcm_    = nullptr;
    Pxa2xxAc97PcmIn* pcm_in_ = nullptr;
    Pxa2xxAc97Modem* modem_  = nullptr;
    Pxa2xxDma*       dma_   = nullptr;
    Ac97Codec*       codec_ = nullptr;

    uint32_t pocr_ = 0, picr_ = 0, mccr_ = 0, gcr_ = 0, mocr_ = 0, micr_ = 0;
};
