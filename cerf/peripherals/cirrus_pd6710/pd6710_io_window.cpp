#include "pd6710_card.h"
#include "pd6710_controller.h"

#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace {

constexpr uint32_t kBase = 0x10010000u;
constexpr uint32_t kSize = 0x00FF03DFu;

class Pd6710IoWindow : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        if (!bd) return false;
        const auto b = bd->GetBoard();
        return b == Board::Smdk2410DevEmu;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint16_t ReadHalf (uint32_t addr) override;
    void     WriteByte (uint32_t addr, uint8_t  value) override;
    void     WriteHalf (uint32_t addr, uint16_t value) override;
};

}  /* namespace */

uint8_t Pd6710IoWindow::ReadByte(uint32_t addr) {
    uint32_t off = addr - kBase;
    auto& ctl = emu_.Get<Pd6710Controller>();
    if (!ctl.MapIoAddress(&off)) {
        LOG(Pcmcia, "[IoWin] read8 +0x%X (no window) -> 0\n", addr - kBase);
        return 0u;
    }
    const uint8_t value = ctl.Card()->ReadByte(off);
    LOG(Pcmcia, "[IoWin] read8 card+0x%X -> 0x%02X\n", off, value);
    return value;
}

uint16_t Pd6710IoWindow::ReadHalf(uint32_t addr) {
    uint32_t off = addr - kBase;
    auto& ctl = emu_.Get<Pd6710Controller>();
    if (!ctl.MapIoAddress(&off)) {
        LOG(Pcmcia, "[IoWin] read16 +0x%X (no window) -> 0\n", addr - kBase);
        return 0u;
    }
    const uint16_t value = ctl.Card()->ReadHalf(off);
    LOG(Pcmcia, "[IoWin] read16 card+0x%X -> 0x%04X\n", off, value);
    return value;
}

void Pd6710IoWindow::WriteByte(uint32_t addr, uint8_t value) {
    uint32_t off = addr - kBase;
    auto& ctl = emu_.Get<Pd6710Controller>();
    if (!ctl.MapIoAddress(&off)) {
        LOG(Pcmcia, "[IoWin] write8 +0x%X = 0x%02X (no window)\n",
            addr - kBase, value);
        return;
    }
    LOG(Pcmcia, "[IoWin] write8 card+0x%X = 0x%02X\n", off, value);
    ctl.Card()->WriteByte(off, value);
}

void Pd6710IoWindow::WriteHalf(uint32_t addr, uint16_t value) {
    uint32_t off = addr - kBase;
    auto& ctl = emu_.Get<Pd6710Controller>();
    if (!ctl.MapIoAddress(&off)) {
        LOG(Pcmcia, "[IoWin] write16 +0x%X = 0x%04X (no window)\n",
            addr - kBase, value);
        return;
    }
    LOG(Pcmcia, "[IoWin] write16 card+0x%X = 0x%04X\n", off, value);
    ctl.Card()->WriteHalf(off, value);
}

REGISTER_SERVICE(Pd6710IoWindow);
