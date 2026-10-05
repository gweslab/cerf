#pragma once

#include "../wolfson_wm97xx/wm97xx_codec.h"

#include <cstdint>

/* symbol_mk500 touch.dll FUN_02238118 @0x02238118 names this part
   "WM9713/14" and matches it on device ID 0x4C13. */
class Wm9713Codec : public Wm97xxCodec {
public:
    using Wm97xxCodec::Wm97xxCodec;

    bool ShouldRegister() override;
    void OnReady() override;

    uint16_t ReadReg(uint32_t reg, uint64_t frame) override;
    void     WriteReg(uint32_t reg, uint16_t value, uint64_t frame) override;

    void ColdReset() override;
    bool DacPowered() override;
    bool AdcPowered() override;

    uint16_t GpioSlotStatus(uint64_t frame) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

protected:
    uint16_t Peek(uint32_t reg) override;
    void     Poke(uint32_t reg, uint16_t value) override;
    const uint16_t* SupportedRates(uint32_t& count) const override;
    bool            IsRateRegister(uint32_t reg) const override;
    bool            RateWriteTakesEffect(uint32_t reg) override;
    uint16_t ConversionData(uint8_t tag) override;
    void     Reconfigure(uint64_t frame, bool poll) override;

private:
    bool PrClear(uint16_t pr_bit) const;
    void ResetRegisters();
    void RequireRegister(uint32_t reg);

    static constexpr uint32_t kNumRegs = 0x80u;
    uint16_t reg_[kNumRegs] = {};
    bool     stalled_poll_  = false;
};
