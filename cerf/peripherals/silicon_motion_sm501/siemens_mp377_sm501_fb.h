#pragma once

#include "siemens_mp377_sm501.h"

#include "../../peripherals/peripheral_base.h"

#include <cstdint>
#include <vector>

namespace siemens_mp377 {

class SiemensMp377Sm501Fb : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;
    uint32_t MmioBase() const override;
    uint32_t MmioSize() const override;
    uint8_t ReadByte(uint32_t a) override;
    uint16_t ReadHalf(uint32_t a) override;
    uint32_t ReadWord(uint32_t a) override;
    void WriteByte(uint32_t a, uint8_t v) override;
    void WriteHalf(uint32_t a, uint16_t v) override;
    void WriteWord(uint32_t a, uint32_t v) override;

    const uint8_t* Vram() const;
    uint8_t* MutableVramFor2d();
    bool WasWritten() const;
    bool WriteVramByte(uint32_t off, uint8_t value);
    bool WriteVramHalf(uint32_t off, uint16_t value);
    bool WriteVramWord(uint32_t off, uint32_t value);
    void Note2dWrite(uint32_t off, uint32_t bytes);
    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    uint32_t CpuVramOffset(uint32_t a);
    void NoteWrite(uint32_t);

    std::vector<uint8_t> vram_;
    bool written_ = false;
};

} // namespace siemens_mp377
