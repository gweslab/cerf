#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "nec_mobilepro_900_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <array>
#include <cstdint>

/* Minimal register stub for the NEC P530 built-in modem's TI TL16C550 UART
   (PA 0x0B000000; 16-bit bus -> register index = offset/2). NOT a modem model:
   returns only the idle status the polled tl16c550.dll driver reads at init so
   boot proceeds; no TX/RX transport, no interrupt line. */
namespace {

class NecMobilePro900ModemUart : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::NecMobilepro900;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    /* 1 MB MMIO band (NEC OAT: VA 0x88300000 -> PA 0x0B000000; page_table_builder
       kOat); the driver touches only the 8 stride-x2 registers in the first 16
       bytes (accessed via the uncached alias 0xA8300000). */
    uint32_t MmioBase() const override { return 0x0B000000u; }
    uint32_t MmioSize() const override { return 0x00100000u; }

    uint8_t  ReadByte (uint32_t addr) override { return static_cast<uint8_t> (ReadReg(addr)); }
    uint16_t ReadHalf (uint32_t addr) override { return static_cast<uint16_t>(ReadReg(addr)); }
    uint32_t ReadWord (uint32_t addr) override { return ReadReg(addr); }
    void WriteByte(uint32_t addr, uint8_t  value) override { WriteReg(addr, value); }
    void WriteHalf(uint32_t addr, uint16_t value) override { WriteReg(addr, value); }
    void WriteWord(uint32_t addr, uint32_t value) override { WriteReg(addr, value); }

    void SaveState(StateWriter& w) override { for (auto v : regs_) w.Write("regs", v); }
    void RestoreState(StateReader& r) override { for (auto& v : regs_) r.Read("regs", v); }

private:
    enum : uint32_t {
        kRbrThr = 0, kIer = 1, kIirFcr = 2, kLcr = 3,
        kMcr = 4, kLsr = 5, kMsr = 6, kScr = 7,
    };

    uint32_t RegIndex(uint32_t addr) const { return (addr - MmioBase()) / 2u; }
    bool dlab() const { return (regs_[kLcr] & 0x80u) != 0u; }

    uint32_t ReadReg(uint32_t addr) {
        const uint32_t idx = RegIndex(addr);
        switch (idx) {
        case kIirFcr: return 0x01u;            /* no interrupt pending -> drain loop exits. */
        case kLsr:    return 0x60u;            /* THRE|TEMT (TX ready); DR=0 (no RX data). */
        case kRbrThr: return dlab() ? regs_[kRbrThr] : 0u;  /* RBR: no input source. */
        default:      return idx < regs_.size() ? regs_[idx] : 0u;
        }
    }
    void WriteReg(uint32_t addr, uint32_t value) {
        const uint32_t idx = RegIndex(addr);
        if (idx < regs_.size()) regs_[idx] = value;  /* SCR scratch, LCR.DLAB, baud divisor, ... */
    }

    std::array<uint32_t, 8> regs_{};
};

}  /* namespace */

REGISTER_SERVICE(NecMobilePro900ModemUart);
