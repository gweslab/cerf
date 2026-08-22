#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>
#include <mutex>

class Pxa2xxGpioSerialSlave {
public:
    virtual ~Pxa2xxGpioSerialSlave() = default;
    virtual void     OnGuestWrite(uint32_t off, uint32_t value) = 0;
    virtual uint32_t DriveGplr(uint32_t bank) = 0;
    virtual void SaveState(StateWriter& w) = 0;
    virtual void RestoreState(StateReader& r) = 0;
};

class Pxa2xxGpio : public Peripheral {
public:
    using Peripheral::Peripheral;

    void     OnReady() override;
    uint32_t MmioBase() const override { return 0x40E00000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SetInputLevel(uint32_t gpio, bool high);
    void SetSerialSlave(Pxa2xxGpioSerialSlave* s) { serial_slave_ = s; }

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

protected:
    enum class Reg { kGplr, kGpdr, kGpsr, kGpcr, kGrer, kGfer, kGedr, kGafr, kNone };

    static constexpr uint32_t kMaxBanks = 4u;
    static constexpr uint32_t kMaxGafr  = 8u;

    virtual uint32_t BankCount() const = 0;
    virtual uint32_t GafrCount() const = 0;
    virtual uint32_t CollectiveMask(uint32_t bank) const = 0;

    /* Intel PXA27x Developer's Manual 280000-001 Table 24-41 (pages 24-33,
       24-34): GPLR0-2 0x00/04/08, GPDR0-2 0x0C/10/14, GPSR0-2 0x18/1C/20,
       GPCR0-2 0x24/28/2C, GRER0-2 0x30/34/38, GFER0-2 0x3C/40/44, GEDR0-2
       0x48/4C/50, GAFR0_L..GAFR3_U 0x54..0x70. */
    virtual Reg Decode(uint32_t off, uint32_t* index) const;

private:
    mutable std::mutex mtx_;

    Pxa2xxGpioSerialSlave* serial_slave_ = nullptr;

    uint32_t in_[kMaxBanks]   = {};
    uint32_t out_[kMaxBanks]  = {};
    uint32_t gpdr_[kMaxBanks] = {};
    uint32_t grer_[kMaxBanks] = {};
    uint32_t gfer_[kMaxBanks] = {};
    uint32_t gedr_[kMaxBanks] = {};
    uint32_t gafr_[kMaxGafr]  = {};

    uint32_t PinLevelLocked(uint32_t bank) const {
        return (out_[bank] & gpdr_[bank]) | (in_[bank] & ~gpdr_[bank]);
    }
    void ApplyEdgesLocked(const uint32_t* before);
    void UpdateIntcLocked();
};
