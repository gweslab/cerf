#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

namespace {

/* SA-1110 Serial Port 2 HSSP (Dev Man §11.10, base 0x80040000): fast-IR half
   of the ICP. HSCR0 +0x60 / HSCR1 +0x64, HSDR +0x6C, HSSR0 +0x74 / HSSR1
   +0x78 (Appendix A). HSSR0/1 must read 0: any service-request or Rx-FIFO
   bit set with no IrDA peer makes the HPIrDA IST spin forever. */
class Sa11xxHssp : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x80040000u; }
    uint32_t MmioSize() const override { return 0x00010000u; }

    uint8_t  ReadByte(uint32_t addr) override {
        return static_cast<uint8_t>(ReadReg(addr - MmioBase()));
    }
    uint16_t ReadHalf(uint32_t addr) override {
        return static_cast<uint16_t>(ReadReg(addr - MmioBase()));
    }
    uint32_t ReadWord(uint32_t addr) override { return ReadReg(addr - MmioBase()); }

    void WriteByte(uint32_t addr, uint8_t  v) override { WriteReg(addr - MmioBase(), v); }
    void WriteHalf(uint32_t addr, uint16_t v) override { WriteReg(addr - MmioBase(), v); }
    void WriteWord(uint32_t addr, uint32_t v) override { WriteReg(addr - MmioBase(), v); }

    void SaveState(StateWriter& w) override {
        w.Write("hscr0", hscr0_);  w.Write("hscr1", hscr1_);
    }
    void RestoreState(StateReader& r) override {
        r.Read("hscr0", hscr0_);  r.Read("hscr1", hscr1_);
    }

private:
    uint32_t ReadReg(uint32_t off) {
        switch (off) {
            case 0x60: return hscr0_;
            case 0x64: return hscr1_;
            case 0x6C: return 0;   /* HSDR: Rx FIFO empty. */
            case 0x74: return 0;   /* HSSR0: idle, no service request/errors. */
            case 0x78: return 0;   /* HSSR1: idle. */
            default:   return 0;   /* reserved/unused. */
        }
    }
    void WriteReg(uint32_t off, uint32_t value) {
        switch (off) {
            case 0x60: hscr0_ = value; return;
            case 0x64: hscr1_ = value; return;
            case 0x6C: return;     /* HSDR Tx: no IrDA peer, byte discarded. */
            case 0x74: return;     /* HSSR0 W1C status: idle, nothing to clear. */
            default:   return;
        }
    }

    uint32_t hscr0_ = 0, hscr1_ = 0;
};

}  /* namespace */

REGISTER_SERVICE(Sa11xxHssp);
