#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>

namespace siemens_mp377 {

inline constexpr uint32_t kMp377Aspc2Base = 0xD0120000u;
inline constexpr uint32_t kMp377Aspc2Size = 0x00001000u;
inline constexpr uint32_t kMp377Aspc2RamVa = 0x9C140000u;
inline constexpr uint32_t kMp377Aspc2RamPa = 0xD0140000u;
inline constexpr uint32_t kMp377Aspc2RamSize = 0x00020000u;

class SiemensMp377Aspc2 : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;
    uint32_t MmioBase() const override;
    uint32_t MmioSize() const override;

    uint8_t ReadByte(uint32_t addr) override;
    uint16_t ReadHalf(uint32_t addr) override;
    uint32_t ReadWord(uint32_t addr) override;
    void WriteByte(uint32_t addr, uint8_t value) override;
    void WriteHalf(uint32_t addr, uint16_t value) override;
    void WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    static constexpr uint32_t kVersionOffset = 0x0Bu;
    static constexpr uint32_t kProbeControlOffset = 0x3Au;
    static constexpr uint32_t kInterruptStatusLoOffset = 0x06u;
    static constexpr uint32_t kInterruptStatusHiOffset = 0x07u;
    static constexpr uint32_t kInterruptEventLoOffset = 0x08u;
    static constexpr uint32_t kInterruptEventHiOffset = 0x09u;
    static constexpr uint32_t kInterruptControlLoOffset = 0x0Au;
    static constexpr uint32_t kServiceControlLoOffset = 0x0Cu;
    static constexpr uint32_t kServiceControlHiOffset = 0x0Du;
    static constexpr uint32_t kAdditionalStatusOffset = 0x38u;
    static constexpr uint32_t kInterruptMaskLoOffset = 0x02u;
    static constexpr uint32_t kInterruptMaskHiOffset = 0x03u;
    static constexpr uint32_t kRequestControlOffset = 0x34u;
    static constexpr uint32_t kInterfaceAddressOffset = 0x27u;
    static constexpr uint32_t kInternalRegisterBase = 0x40u;
    static constexpr uint32_t kMode0Offset = kInternalRegisterBase;
    static constexpr uint8_t kE2PlusVersion = 4u;
    uint8_t probe_control_ = 0u;
    uint8_t interrupt_control_lo_ = 0u;
    uint8_t interrupt_control_hi_ = 0u;
    uint8_t interrupt_mask_lo_ = 0u;
    uint8_t interrupt_mask_hi_ = 0u;
    uint8_t request_control_ = 0u;
    uint8_t mode0_ = 0u;
    uint8_t interrupt_event_lo_ = 0u;
    uint8_t interrupt_event_hi_ = 0u;
    uint8_t interface_address_ = 0u;
    uint8_t service_control_lo_ = 0u;
    uint8_t service_control_hi_ = 0u;
};

} // namespace siemens_mp377
