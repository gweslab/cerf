#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../board_detector.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <mutex>

namespace {

constexpr uint32_t kBase = 0x500F0000u;
constexpr uint32_t kSize = 0x00002120u;

class DevEmuDmaTransport : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::Smdk2410DevEmu;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint16_t ReadHalf (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte (uint32_t addr, uint8_t  value) override;
    void     WriteHalf (uint32_t addr, uint16_t value) override;
    void     WriteWord (uint32_t addr, uint32_t value) override;

private:
    mutable std::mutex   state_mutex_;
    std::array<uint8_t, kSize> shadow_ {};
};

uint8_t DevEmuDmaTransport::ReadByte(uint32_t addr) {
    const uint32_t off = addr - kBase;
    uint8_t value;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        value = shadow_[off];
    }
    LOG(Net, "[DMATransport] read8  +0x%04X -> 0x%02X (stub)\n", off, value);
    return value;
}

uint16_t DevEmuDmaTransport::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - kBase;
    uint16_t value;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        std::memcpy(&value, &shadow_[off], 2);
    }
    LOG(Net, "[DMATransport] read16 +0x%04X -> 0x%04X (stub)\n", off, value);
    return value;
}

uint32_t DevEmuDmaTransport::ReadWord(uint32_t addr) {
    const uint32_t off = addr - kBase;
    uint32_t value;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        std::memcpy(&value, &shadow_[off], 4);
    }
    LOG(Net, "[DMATransport] read32 +0x%04X -> 0x%08X (stub)\n", off, value);
    return value;
}

void DevEmuDmaTransport::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = addr - kBase;
    LOG(Net, "[DMATransport] write8  +0x%04X = 0x%02X (stub)\n", off, value);
    std::lock_guard<std::mutex> lk(state_mutex_);
    shadow_[off] = value;
}

void DevEmuDmaTransport::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - kBase;
    LOG(Net, "[DMATransport] write16 +0x%04X = 0x%04X (stub)\n", off, value);
    std::lock_guard<std::mutex> lk(state_mutex_);
    std::memcpy(&shadow_[off], &value, 2);
}

void DevEmuDmaTransport::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - kBase;
    LOG(Net, "[DMATransport] write32 +0x%04X = 0x%08X (stub)\n", off, value);
    std::lock_guard<std::mutex> lk(state_mutex_);
    std::memcpy(&shadow_[off], &value, 4);
}

}  /* namespace */

REGISTER_SERVICE(DevEmuDmaTransport);
