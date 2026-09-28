#pragma once

#include "../../peripherals/peripheral_base.h"
#include "../guest_cpu_reset.h"
#include "../intel_rtc_counter.h"

#include <cstdint>

class Sa11xxRtc : public Peripheral {
public:
    explicit Sa11xxRtc(CerfEmulator& emu);

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x90010000u; }
    uint32_t MmioSize() const override { return 0x00010000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

    int64_t AlarmWakeDueNs();
    void    CreditCoreStop(uint64_t ns);

private:
    void     PushLevel();
    void     OnResetLine(ResetLineKind kind);
    uint32_t ReadReg(uint32_t off) const;
    void     WriteReg(uint32_t off, uint32_t value);

    IntelRtcCounter rtc_;
};
