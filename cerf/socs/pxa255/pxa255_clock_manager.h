#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>
#include <functional>
#include <vector>

class Pxa255ClockManager : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x41300000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override { ApplyRate(); }

    bool OscillatorOk() const { return ook_; }
    void RegisterOscillatorListener(std::function<void()> fn);
    void SetOscillatorStable();
    void WriteClkcfg(uint32_t value);

    static uint32_t __fastcall ReadClkcfgHelper(Pxa255ClockManager* self);
    static void __fastcall WriteClkcfgHelper(Pxa255ClockManager* self, uint32_t value);

private:
    static constexpr uint32_t kCccrMask    = 0x000003FFu;
    static constexpr uint32_t kCkenMask    = 0x00017BFFu;
    static constexpr uint32_t kCccrReset   = 0x00000121u;
    static constexpr uint32_t kCkenReset   = 0x00017BFFu;
    static constexpr uint32_t kClkcfgTurbo = 0x1u;
    static constexpr uint32_t kClkcfgFcs   = 0x2u;
    static constexpr uint32_t kClkcfgMask  = kClkcfgTurbo | kClkcfgFcs;
    static constexpr uint32_t kOsccOok     = 0x1u;
    static constexpr uint32_t kOsccOon     = 0x2u;

    void     LoadPll(const char* when);
    bool     Supported(uint32_t cccr, bool turbo) const;
    uint64_t CoreHz(uint32_t cccr, bool turbo) const;
    void     ApplyRate();

    uint32_t cccr_        = kCccrReset;
    uint32_t loaded_cccr_ = kCccrReset;
    uint32_t cclkcfg_     = 0;
    uint32_t cken_        = kCkenReset;
    bool     oon_         = false;
    bool     ook_         = false;

    std::vector<std::function<void()>> osc_listeners_;
};
