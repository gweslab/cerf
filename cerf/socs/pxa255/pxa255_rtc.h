#pragma once

#include "../../peripherals/peripheral_base.h"
#include "../guest_cpu_reset.h"
#include "../intel_rtc_counter.h"

#include <cstdint>

class Pxa255Rtc : public Peripheral {
public:
    explicit Pxa255Rtc(CerfEmulator& emu);

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x40900000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

private:
    void ApplyOscillator();
    void PushLevel();
    void OnResetLine(ResetLineKind kind);
    void WriteRttr(uint32_t value);

    IntelRtcCounter rtc_;
    uint64_t        alarm_mark_ = 0;
    uint64_t        match_mark_ = 0;
};
