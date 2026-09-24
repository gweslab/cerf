#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "nec_mobilepro_900_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <array>
#include <cstdint>

namespace {

/* NEC P530 board embedded controller (PA 0x0D000000): command/response MCU
   addressed as a register file. Wire protocol RE'd from phcd.dll (sub_1B7F34C
   read / sub_1B7F3B0 write); see the off0/off2 handlers below. */
class NecMobilePro900BoardEc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::NecMobilepro900;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return 0x0D000000u; }
    uint32_t MmioSize() const override { return 0x00100000u; }

    /* off0 is the data port: a register value is transferred as two 16-bit
       accesses, low word then high word (phase_ tracks which). */
    uint16_t ReadHalf(uint32_t addr) override {
        if ((addr - MmioBase()) != 0u) return 0u;
        const uint32_t v = reg_[cur_reg_];
        const uint16_t half = phase_ ? static_cast<uint16_t>(v >> 16)
                                     : static_cast<uint16_t>(v & 0xFFFFu);
        phase_ ^= 1u;
        return half;
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        const uint32_t off = addr - MmioBase();
        if (off == 2u) {                       /* command: bits[6:0]=reg, bit7=write. */
            cur_reg_ = value & 0x7Fu;
            phase_   = 0u;
            return;
        }
        if (off != 0u) return;
        if (phase_ == 0u) {
            reg_[cur_reg_] = (reg_[cur_reg_] & 0xFFFF0000u) | value;
            phase_ = 1u;
        } else {
            reg_[cur_reg_] = (reg_[cur_reg_] & 0x0000FFFFu) |
                             (static_cast<uint32_t>(value) << 16);
            phase_ = 0u;
            /* Reg 2 bit0 is the controller-reset strobe: phcd (sub_1B7FBB4) sets it
               then spins until the EC clears it, so complete the reset here. */
            if (cur_reg_ == 2u) reg_[2] &= ~1u;
        }
    }

    /* Drivers use 16-bit (USHORT) port access; route byte/word onto it defensively. */
    uint8_t  ReadByte (uint32_t addr) override { return static_cast<uint8_t>(ReadHalf(addr)); }
    uint32_t ReadWord (uint32_t addr) override { return ReadHalf(addr); }
    void WriteByte(uint32_t addr, uint8_t  v) override { WriteHalf(addr, v); }
    void WriteWord(uint32_t addr, uint32_t v) override { WriteHalf(addr, static_cast<uint16_t>(v)); }

    void SaveState(StateWriter& w) override {
        w.Write("cur_reg", cur_reg_); w.Write("phase", phase_);
        for (auto r : reg_) w.Write("reg", r);
    }
    void RestoreState(StateReader& r) override {
        r.Read("cur_reg", cur_reg_); r.Read("phase", phase_);
        for (auto& x : reg_) r.Read("reg", x);
    }

private:
    uint32_t cur_reg_ = 0;
    uint32_t phase_   = 0;
    std::array<uint32_t, 128> reg_{};
};

}  /* namespace */

REGISTER_SERVICE(NecMobilePro900BoardEc);
