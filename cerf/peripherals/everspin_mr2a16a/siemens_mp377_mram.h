#pragma once

#include "../../peripherals/peripheral_base.h"

#include <array>
#include <cstdint>

namespace siemens_mp377 {

inline constexpr uint32_t kMp377MramBase = 0xD0000000u;
inline constexpr uint32_t kMp377MramSize = 0x00080000u;
inline constexpr uint32_t kMp377MramAliasPa = 0xF0080000u;
inline constexpr uint32_t kMp377BspioBootStateOffset = 0x0007FFDCu;
inline constexpr uint32_t kMp377BspioBootStateUpdateOnce = 0x96A50008u;

class SiemensMp377Mram : public Peripheral {
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

    uint8_t ReadAliasByte(uint32_t alias_pa) const;
    void WriteAliasByte(uint32_t alias_pa, uint8_t value);
    void SeedBspioBootState();

private:
    void ResetErased();
    uint32_t OffsetFromAlias(uint32_t alias_pa) const;
    void PutLe32(uint32_t off, uint32_t value);

    std::array<uint8_t, kMp377MramSize> mram_{};
};

} // namespace siemens_mp377
