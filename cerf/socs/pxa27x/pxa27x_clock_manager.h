#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>
#include <functional>
#include <vector>

class Pxa27xClockManager : public Peripheral {
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

    bool OscillatorOk() const { return (oscc_ & kOsccOok) != 0u; }
    void RegisterOscillatorListener(std::function<void()> fn);
    void SetOscillatorStable();
    void WriteClkcfg(uint32_t value);

    uint64_t LcdClockHz() const;
    bool     LcdClockEnabled() const { return (cken_ & kCkenLcd) != 0u; }
    void     RegisterLcdClockListener(std::function<void()> fn);

    bool ClockEnabled(uint32_t cken_bit) const { return (cken_ & (1u << cken_bit)) != 0u; }
    void RegisterClockEnableListener(std::function<void(uint32_t old_cken)> fn);

    static uint32_t __fastcall ReadClkcfgHelper(Pxa27xClockManager* self);
    static void __fastcall WriteClkcfgHelper(Pxa27xClockManager* self, uint32_t value);

private:
    static constexpr uint32_t kCccrMask   = 0xCE00079Fu;
    static constexpr uint32_t kCkenMask   = 0x81FFFFFFu;
    static constexpr uint32_t kOsccMask   = 0x0000006Eu;
    static constexpr uint32_t kOsccOon    = 0x00000002u;
    static constexpr uint32_t kOsccOok    = 0x00000001u;
    static constexpr uint32_t kCccrReset  = 0x00000107u;
    static constexpr uint32_t kCkenReset  = 0x81FFFFFFu;
    /* Intel PXA27x Developer's Manual 280000-001 Table 3-33 (page 3-98): CKEN[16]
       "LCD Controller Clock Enable". */
    static constexpr uint32_t kCkenLcd    = 1u << 16;
    static constexpr uint32_t kCccrPllOff = 0xC0000000u;
    static constexpr uint32_t kClkcfgT    = 0x1u;
    static constexpr uint32_t kClkcfgF    = 0x2u;
    static constexpr uint32_t kClkcfgHt   = 0x4u;
    static constexpr uint32_t kClkcfgMask = 0xFu;

    void     FireOscillatorListeners();
    void     LoadPll(const char* when);
    bool     Supported(uint32_t cccr, uint32_t clkcfg) const;
    uint64_t CoreHz(uint32_t cccr, uint32_t clkcfg) const;
    void     ApplyRate();
    void     PublishLcdClock();

    uint32_t cccr_        = kCccrReset;
    uint32_t loaded_cccr_ = kCccrReset;
    uint32_t clkcfg_      = 0u;
    uint32_t cken_        = kCkenReset;
    uint32_t oscc_        = 0u;

    std::vector<std::function<void()>> osc_listeners_;
    std::vector<std::function<void()>> lcd_clock_listeners_;
    std::vector<std::function<void(uint32_t)>> cken_listeners_;
    uint64_t                           published_lcd_hz_ = 0u;
    bool                               published_lcd_on_ = false;
};
