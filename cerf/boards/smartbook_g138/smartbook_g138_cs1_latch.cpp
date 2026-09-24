#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../board_context.h"
#include "smartbook_g138_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

/* G138 board-control latch on nCS1 (PA 0x08000000): OAL firmware-init
   (nk.exe sub_8C17962C) writes halfword 0 to +0/+2/+4, never reads. The OAT
   backs CS1 read-only so reads come from that backing and only writes reach
   here; reads keep the loud-halt default so a read arriving here surfaces. */
class SmartBookG138Cs1Latch : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SmartbookG138;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x08000000u; }
    uint32_t MmioSize() const override { return 0x00000010u; }

    void WriteByte(uint32_t addr, uint8_t  value) override { Store(addr, value, 1); }
    void WriteHalf(uint32_t addr, uint16_t value) override { Store(addr, value, 2); }
    void WriteWord(uint32_t addr, uint32_t value) override { Store(addr, value, 4); }

    void SaveState(StateWriter& w) override { w.WriteBytes("shadow", shadow_, sizeof(shadow_)); }
    void RestoreState(StateReader& r) override { r.ReadBytes("shadow", shadow_, sizeof(shadow_)); }

private:
    void Store(uint32_t addr, uint32_t value, uint32_t bytes) {
        const uint32_t off = addr - MmioBase();
        for (uint32_t i = 0; i < bytes; ++i)
            shadow_[(off + i) & 0xFu] = static_cast<uint8_t>(value >> (i * 8));
        LOG(Board, "SmartBookG138Cs1Latch: +0x%02X <= 0x%08X (%u-byte)\n",
            off, value, bytes);
    }

    uint8_t shadow_[0x10] = {};
};

}  /* namespace */

REGISTER_SERVICE(SmartBookG138Cs1Latch);
