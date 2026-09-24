#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../board_context.h"
#include "smartbook_g138_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

/* G138 board-config block on static nCS4 (PA 0x42000000), unbacked MMIO. OAL
   firmware-init (nk.exe sub_8C17962C) writes +0x30E=1 then reads board
   type/version/S/N at +0x304/306/308 - info-only (board-type string is
   MPU-derived), and the PLD data isn't in the ROM, so reads return 0. */
class SmartBookG138Cs4BoardConfig : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SmartbookG138;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x42000000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint8_t  ReadByte(uint32_t addr) override { return static_cast<uint8_t>(Read(addr)); }
    uint16_t ReadHalf(uint32_t addr) override { return static_cast<uint16_t>(Read(addr)); }
    uint32_t ReadWord(uint32_t addr) override { return Read(addr); }

    void WriteByte(uint32_t addr, uint8_t  value) override { Write(addr, value); }
    void WriteHalf(uint32_t addr, uint16_t value) override { Write(addr, value); }
    void WriteWord(uint32_t addr, uint32_t value) override { Write(addr, value); }

    void SaveState(StateWriter& w) override { w.Write("enable", enable_); }
    void RestoreState(StateReader& r) override { r.Read("enable", enable_); }

private:
    uint32_t Read(uint32_t addr) {
        const uint32_t off = addr - MmioBase();
        LOG(Board, "SmartBookG138Cs4BoardConfig: read +0x%03X -> 0 (config not in ROM)\n", off);
        return 0u;
    }
    void Write(uint32_t addr, uint32_t value) {
        const uint32_t off = addr - MmioBase();
        if (off == 0x30Eu) enable_ = value & 0xFFFFu;
        LOG(Board, "SmartBookG138Cs4BoardConfig: write +0x%03X <= 0x%08X\n", off, value);
    }

    uint32_t enable_ = 0;
};

}  /* namespace */

REGISTER_SERVICE(SmartBookG138Cs4BoardConfig);
