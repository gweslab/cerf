#include "pd6710_card.h"
#include "pd6710_controller.h"

#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace {

constexpr uint32_t kBase = 0x10000000u;
constexpr uint32_t kSize = 0x0000FFFFu;

class Pd6710MemWindow : public Peripheral {
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

uint8_t Pd6710MemWindow::ReadByte(uint32_t addr) {
    const uint32_t off = addr - kBase;
    auto& ctl = emu_.Get<Pd6710Controller>();
    Pd6710Card* card = ctl.IsCardPowered() ? ctl.Card() : nullptr;
    const uint8_t value = card ? card->ReadMemoryByte(off) : 0u;
    LOG(Pcmcia, "[MemWin] read8 +0x%X -> 0x%02X%s\n",
        off, value, card ? "" : " (no card)");
    return value;
}

uint16_t Pd6710MemWindow::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - kBase;
    auto& ctl = emu_.Get<Pd6710Controller>();
    Pd6710Card* card = ctl.IsCardPowered() ? ctl.Card() : nullptr;
    const uint16_t value = card ? card->ReadMemoryHalf(off) : 0u;
    LOG(Pcmcia, "[MemWin] read16 +0x%X -> 0x%04X%s\n",
        off, value, card ? "" : " (no card)");
    return value;
}

void Pd6710MemWindow::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = addr - kBase;
    auto& ctl = emu_.Get<Pd6710Controller>();
    Pd6710Card* card = ctl.IsCardPowered() ? ctl.Card() : nullptr;
    LOG(Pcmcia, "[MemWin] write8 +0x%X = 0x%02X%s\n",
        off, value, card ? "" : " (no card)");
    if (card) card->WriteMemoryByte(off, value);
}

void Pd6710MemWindow::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - kBase;
    auto& ctl = emu_.Get<Pd6710Controller>();
    Pd6710Card* card = ctl.IsCardPowered() ? ctl.Card() : nullptr;
    LOG(Pcmcia, "[MemWin] write16 +0x%X = 0x%04X%s\n",
        off, value, card ? "" : " (no card)");
    if (card) card->WriteMemoryHalf(off, value);
}

REGISTER_SERVICE(Pd6710MemWindow);
