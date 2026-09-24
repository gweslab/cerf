#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

namespace {

/* SA-1110 Memory Controller - Dev Man §10.2 Table 10-2 register map.
   All registers R/W; CERF treats them as plain storage (the actual
   DRAM/SDRAM timing they configure has no effect on emulator memory
   access - the host backs DRAM with normal allocations). */

class Sa11xxMemoryController : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0xA0000000u; }
    uint32_t MmioSize() const override { return 0x00010000u; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override    { w.WriteBytes("regs", regs_, sizeof(regs_)); }
    void RestoreState(StateReader& r) override { r.ReadBytes("regs", regs_, sizeof(regs_)); }

private:
    /* §10.2 Table 10-2 (offsets 0x00-0x2C) + §10.3 SMCNFG (+0x30). */
    uint32_t regs_[13] = {};

    static bool OffsetToIndex(uint32_t off, uint32_t* index_out) {
        if (off > 0x30 || (off & 0x3u) != 0) return false;
        *index_out = off / 4u;
        return true;
    }
};

uint8_t Sa11xxMemoryController::ReadByte(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    uint32_t index;
    if (!OffsetToIndex(base, &index)) HaltUnsupportedAccess("ReadByte", addr, 0);
    return static_cast<uint8_t>((regs_[index] >> shift) & 0xFFu);
}

uint32_t Sa11xxMemoryController::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    uint32_t index;
    if (!OffsetToIndex(off, &index)) HaltUnsupportedAccess("ReadWord", addr, 0);
    return regs_[index];
}

void Sa11xxMemoryController::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    uint32_t index;
    if (!OffsetToIndex(base, &index)) HaltUnsupportedAccess("WriteByte", addr, value);
    const uint32_t cur     = regs_[index];
    const uint32_t cleared = cur & ~(0xFFu << shift);
    regs_[index] = cleared | (static_cast<uint32_t>(value) << shift);
}

void Sa11xxMemoryController::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    uint32_t index;
    if (!OffsetToIndex(off, &index)) HaltUnsupportedAccess("WriteWord", addr, value);
    regs_[index] = value;
}

}  /* namespace */

REGISTER_SERVICE(Sa11xxMemoryController);
