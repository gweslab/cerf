#pragma once

#include "../open_bus_window.h"

#include <cstdint>
#include <vector>

/* VR4111 UM Table 6-7 p.167; casio_cassiopeia_e55 dic2.dll DicAlloc @0x13D0CE4
   maps PA 0x1E000000 / 0x800000 (KSEG1 0xBE000000). */
class CasioDictionaryRomWindow : public OpenBusWindow {
public:
    using OpenBusWindow::OpenBusWindow;

    void OnReady() override;

    uint32_t MmioBase() const override { return 0x1E000000u; }
    uint32_t MmioSize() const override { return 0x00800000u; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint16_t ReadHalf (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;

    void WriteByte (uint32_t addr, uint8_t  value) override;
    void WriteHalf (uint32_t addr, uint16_t value) override;
    void WriteWord (uint32_t addr, uint32_t value) override;

private:
    std::vector<uint8_t> data_;
};
