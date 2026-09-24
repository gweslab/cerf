#include "../peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../../boards/simpad_sl4/simpad_sl4_id.h"
#include "../../state/state_stream.h"
#include "../peripheral_dispatcher.h"

#include <array>
#include <cstdint>

namespace {

/* Philips TDA8007B smart-card IC (SIMpad SL4 nCS4, PA 0x40000000): 16 byte
   registers at 4-byte stride (tda8007b.dll SCR: sub_1292B20 write / sub_1292B60
   read). Empty-reader stub - writes store config, reads return cleared/idle so
   SCR_Init completes (reg 15 ready-poll breaks on 0, reg 12 bit2 = no card). */
class PhilipsTda8007b : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SimpadSl4;
    }

    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x40000000u; }
    uint32_t MmioSize() const override { return kNumRegs * 4u; }

    uint8_t ReadByte(uint32_t addr) override { return regs_[RegIndex(addr, 0)]; }
    void    WriteByte(uint32_t addr, uint8_t value) override {
        regs_[RegIndex(addr, value)] = value;
    }

    /* The 16 byte registers are the whole SCR state - writes land here,
       reads come straight back. No host-only members to skip. */
    void SaveState(StateWriter& w) override {
        w.WriteBytes("regs", regs_.data(), regs_.size());
    }
    void RestoreState(StateReader& r) override {
        r.ReadBytes("regs", regs_.data(), regs_.size());
    }

private:
    static constexpr uint32_t kNumRegs = 16u;

    uint32_t RegIndex(uint32_t addr, uint32_t value) {
        const uint32_t off = addr - MmioBase();
        if ((off & 0x3u) != 0 || (off >> 2) >= kNumRegs)
            HaltUnsupportedAccess("TDA8007B register", addr, value);
        return off >> 2;
    }

    std::array<uint8_t, kNumRegs> regs_{};
};

}  /* namespace */

REGISTER_SERVICE(PhilipsTda8007b);
