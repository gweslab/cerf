#pragma once

#include <cstdint>

#include "../../peripherals/peripheral_base.h"
#include "../spi_slave.h"

class S3C2410Spi : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    /* S3C2410A UM p. 22-7: SPCON0 0x59000000, SPCON1 0x59000020. */
    void SetSlave(int channel, SpiSlave* slave);

    uint32_t MmioBase() const override { return 0x59000000u; }
    uint32_t MmioSize() const override { return 0x00100000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState   (StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    static constexpr int kChannels = 2;

    /* S3C2410A UM pp. 22-7..22-10, Reset Value columns. */
    struct Channel {
        uint32_t spcon  = 0x00u;
        uint32_t spsta  = 0x01u;
        uint32_t sppin  = 0x02u;
        uint32_t sppre  = 0x00u;
        uint32_t sptdat = 0x00u;
        uint32_t sprdat = 0x00u;
    };

    template <typename F>
    static constexpr void VisitChannel(Channel& c, F& field) {
        field("spcon", c.spcon);
        field("spsta", c.spsta);
        field("sppin", c.sppin);
        field("sppre", c.sppre);
        field("sptdat", c.sptdat);
        field("sprdat", c.sprdat);
    }

    void Reset();
    void Transfer(int channel, uint8_t tx);

    Channel   channel_[kChannels];
    SpiSlave* slave_[kChannels] = {};
};
