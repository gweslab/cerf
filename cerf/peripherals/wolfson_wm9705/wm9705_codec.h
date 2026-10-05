#pragma once

#include "../wolfson_wm97xx/wm97xx_codec.h"

#include <cstdint>

class Wm9705Codec : public Wm97xxCodec {
public:
    using Wm97xxCodec::Wm97xxCodec;

    bool ShouldRegister() override;
    void OnReady() override;

    uint16_t ReadReg(uint32_t reg, uint64_t frame) override;
    void     WriteReg(uint32_t reg, uint16_t value, uint64_t frame) override;

    void ColdReset() override;
    bool DacPowered() override;
    bool AdcPowered() override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

protected:
    uint16_t Peek(uint32_t reg) override;
    void     Poke(uint32_t reg, uint16_t value) override;
    const uint16_t* SupportedRates(uint32_t& count) const override;
    uint16_t ConversionData(uint8_t tag) override;
    void     Reconfigure(uint64_t frame, bool poll) override;

private:
    void LoadDefaults();
    void RequireRegister(uint32_t reg);

    static constexpr uint32_t kNumRegs = 512u;
    uint16_t reg_[kNumRegs] = {};
};
