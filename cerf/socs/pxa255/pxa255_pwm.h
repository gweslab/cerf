#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

/* PXA255 Pulse Width Modulator (manual §4.5, Table 4-46/47/48). Two channels
   at 0x40B00000 (PWM0) and 0x40C00000 (PWM1); a concrete supplies MmioBase.
   The three registers are write-only config with NO status register, so
   storage IS the complete behaviour — not a stub to flesh out. The Falcon
   backlight (backlite.dll InitializeBacklightHardware) writes them to set
   brightness and faults on the unmapped region. */
class Pxa255Pwm : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::PXA25x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord(uint32_t addr) override {
        switch (addr - MmioBase()) {
        case kCTRL:   return ctrl_;
        case kDUTY:   return duty_;
        case kPERVAL: return perval_;
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        switch (addr - MmioBase()) {
        case kCTRL:   ctrl_   = value & 0x00FFu; return;  /* SD|PRESCALE (Table 4-46). */
        case kDUTY:   duty_   = value & 0x07FFu; return;  /* FDCYCLE|DCYCLE (Table 4-47). */
        case kPERVAL: perval_ = value & 0x03FFu; return;  /* PV (Table 4-48). */
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

private:
    enum : uint32_t { kCTRL = 0x00u, kDUTY = 0x04u, kPERVAL = 0x08u };
    uint32_t ctrl_ = 0, duty_ = 0, perval_ = 0;
};
