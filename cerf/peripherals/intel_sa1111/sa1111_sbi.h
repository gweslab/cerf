#pragma once

#include "sa1111_unit.h"

#include <cstdint>
#include <functional>
#include <vector>

class Sa1111Sbi : public Sa1111Unit {
public:
    using Sa1111Unit::Sa1111Unit;

    enum class Mbgnt    { Arbiter, Low, High, Undetermined };
    enum class BusGrant { Granted, Stalled, Undetermined };

    bool ShouldRegister() override;

    uint32_t MmioBase() const override { return 0x40000000u; }
    uint32_t MmioSize() const override { return 0x00000200u; }

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

    void SetHostPins(std::function<Mbgnt()> mbgnt, std::function<bool()> clk_3686400);
    void OnHostPinsChange();
    void RegisterGrantListener(std::function<void()> fn);
    void RegisterClkInputListener(std::function<void()> fn);

    uint32_t Skcr() const { return skcr_; }
    bool PllClockSelected() const;
    bool PllClockRunning() const { return PllClockSelected() && !LowPowerRequested(); }
    bool BusClocksEnabled() const { return (skcr_ & kSkcrRclkEn) != 0u; }
    bool I2sSelected() const { return (skcr_ & kSkcrSeLac) == 0u; }
    bool LowPowerRequested() const { return (skcr_ & (kSkcrSleep | kSkcrDoze)) != 0u; }
    bool SleepRequested() const { return (skcr_ & kSkcrSleep) != 0u; }
    bool ClockInputModelled() const;
    bool ClockDisturbed() const { return clock_disturbed_; }
    BusGrant Grant() const;

    uint32_t CasLatency() const { return (smcr_ & kSmcrClat) != 0u ? 3u : 2u; }
    uint64_t BurstWordCycles(uint32_t word, uint64_t cpu_hz, uint32_t cas) const;
    uint64_t BusReleaseCycles() const;

protected:
    bool     ClockedByRclk() const override { return false; }
    void     OnChipReset(bool held) override;
    uint32_t UnitReadWord (uint32_t addr) override;
    void     UnitWriteWord(uint32_t addr, uint32_t value) override;

private:
    void RequireAwake(uint32_t addr) const;
    void RequireRclk(uint32_t addr) const;
    void NotifyGrant();

    std::function<Mbgnt()> mbgnt_;
    std::function<bool()>  clk_3686400_;
    std::vector<std::function<void()>> grant_listeners_;
    std::vector<std::function<void()>> clk_input_listeners_;
    bool clk_seen_        = false;
    bool clock_disturbed_ = false;

    /* SA-1111 Developer's Manual Table 3-9: PLL_Bypass bit 0 "1 = Enable, 0 = Bypass",
       RCLKEn bit 1 "(RCLK and DCLK)", Sleep bit 2 "Force entry into Sleep mode", Doze bit 3
       "Force entry into Doze mode", VCO_OFF bit 4 "1= Off", SeLAC bit 8 "1 = AC Link". */
    static constexpr uint32_t kSkcrPllBypass = 1u << 0;
    static constexpr uint32_t kSkcrRclkEn    = 1u << 1;
    static constexpr uint32_t kSkcrSleep     = 1u << 2;
    static constexpr uint32_t kSkcrDoze      = 1u << 3;
    static constexpr uint32_t kSkcrVcoOff    = 1u << 4;
    static constexpr uint32_t kSkcrSeLac     = 1u << 8;

    static constexpr uint32_t kSkcrReset = 0x80u;   /* RdyEn reset (Table 3-9). */
    static constexpr uint32_t kSmcrReset = 0x35u;   /* DTIM|DRAC=5|CLAT reset (Table 3-10). */
    /* Table 3-10: DTIM bit 0 "1 = SDRAM", MBGE bit 1 "1=MBGNT is enabled", CLAT bit 5
       "1 = CAS latency = 3". §3.2.3.5: "SDCLK - 48 MHz clock". */
    static constexpr uint32_t kSmcrDtim = 1u << 0;
    static constexpr uint32_t kSmcrMbge = 1u << 1;
    static constexpr uint32_t kSmcrClat = 1u << 5;
    static constexpr uint64_t kSdclkHz  = 48000000u;

    /* Table 3-3 note 1: "All reserved bits are read back as zero." Table 3-9 SKCR bits
       11:0; Table 3-10 SMCR bits 5:0. */
    static constexpr uint32_t kSkcrDefined = 0xFFFu;
    static constexpr uint32_t kSmcrDefined = 0x3Fu;

    uint32_t skcr_ = kSkcrReset;
    uint32_t smcr_ = kSmcrReset;
};
