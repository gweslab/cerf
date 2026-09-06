#pragma once

#include "../../peripherals/peripheral_base.h"

#include <atomic>
#include <cstdint>

class StateWriter;
class StateReader;

/* Write-only latch, pins 0..15 at H3600_EGPIO_PHYS = SA1100_CS5_PHYS +
   0x01000000: Linux arch/arm/mach-sa1100/include/mach/h3xxx.h. Bit 10 (0x400)
   AUD_ON "Enables power to audio output amp", O(H): NetBSD
   sys/arch/hpcarm/dev/ipaq_gpioreg.h. */
class IpaqGen1Egpio : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x49000000u; }
    uint32_t MmioSize() const override { return 0x00000004u; }

    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

    uint16_t Latched() const { return latched_.load(std::memory_order_acquire); }

    static constexpr uint16_t kAudioOutputEnable = 0x400u;

private:
    void NotifySink();
    void StoreLatch(const char* op, uint32_t addr, uint32_t value);

    std::atomic<uint16_t> latched_{0};
};
