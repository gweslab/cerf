#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

/* Intel PXA27x Developer's Manual 280000-001 Table 27-34 (page 27-43):
   0x5000_0000 CICR0 / 0004 CICR1 / 0008 CICR2 / 000C CICR3 / 0010 CICR4 /
   0014 CISR / 0018 CIFR / 001C CITOR / 0028 CIBR0 / 0030 CIBR1 / 0038 CIBR2. */
class Pxa27xQuickCapture : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA27x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x50000000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (IsRegister(off)) return regs_[off / 4u];
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        switch (off) {
        /* Section 27.5.7: "To clear a CISR status bit, write 0b1 to it.
           Writing 0b0 to a status bit has no effect." */
        case kCisr:
            regs_[kCisr / 4u] &= ~(value & kCisrMask);
            return;
        /* Table 27-32 (page 27-41) CIFR[3] RESETF "is automatically cleared
           after resetting the pointers"; 29:8 FLVL2/1/0 are R. */
        case kCifr:
            regs_[kCifr / 4u] = value & kCifrMask & ~kCifrResetf;
            return;
        /* Table 27-33 (page 27-42): CIBR0/1/2 bits 31:0 are R. */
        case kCibr0:
        case kCibr1:
        case kCibr2:
            return;
        default:
            break;
        }
        if (IsRegister(off)) { regs_[off / 4u] = value & MaskOf(off); return; }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

    void SaveState(StateWriter& w) override { w.WriteBytes(regs_, sizeof(regs_)); }
    void RestoreState(StateReader& r) override { r.ReadBytes(regs_, sizeof(regs_)); }

private:
    enum : uint32_t {
        kCicr0 = 0x00, kCicr1 = 0x04, kCicr2 = 0x08, kCicr3 = 0x0C,
        kCicr4 = 0x10, kCisr  = 0x14, kCifr  = 0x18, kCitor = 0x1C,
        kCibr0 = 0x28, kCibr1 = 0x30, kCibr2 = 0x38,
    };

    /* Table 27-31 (page 27-39): CISR 31:16 reserved, 15:0 R/WC. Table 27-32
       (page 27-41): CIFR 5:4 THL_0, 3 RESETF, 2:0 FEN2/FEN1/FEN0. */
    enum : uint32_t {
        kCisrMask   = 0x0000FFFFu,
        kCifrMask   = 0x0000003Fu,
        kCifrResetf = 0x00000008u,
    };

    static bool IsRegister(uint32_t off) {
        switch (off) {
        case kCicr0: case kCicr1: case kCicr2: case kCicr3: case kCicr4:
        case kCisr:  case kCifr:  case kCitor:
        case kCibr0: case kCibr1: case kCibr2:
            return true;
        default:
            return false;
        }
    }

    static uint32_t MaskOf(uint32_t off) {
        switch (off) {
        /* Table 27-24 (page 27-27): CICR0 23:10 reserved. */
        case kCicr0: return 0xFF0003FFu;
        /* Table 27-26 (page 27-30): CICR1 28:26 reserved. */
        case kCicr1: return 0xE3FFFFFFu;
        /* Table 27-27 (page 27-33): CICR2 bit 9 reserved. */
        case kCicr2: return 0xFFFFFDFFu;
        /* Table 27-29 (page 27-36): CICR4 31:27 and 18:11 reserved. */
        case kCicr4: return 0x07F807FFu;
        /* Table 27-28 (page 27-34) CICR3 31:0 R/W; Table 27-30 (page 27-37)
           CITOR 31:0 R/W TIMEOUT. */
        default:     return 0xFFFFFFFFu;
        }
    }

    /* Table 27-24 (page 27-27) CICR0 reset row sets defined bits 9:0 (TOM,
       RDAVM, FEM, EOLM, PERRM, QDM, CDM, SOFM, EOFM, FOM); every other QCI
       reset row is 0. */
    uint32_t regs_[(kCibr2 / 4u) + 1u] = { 0x000003FFu };
};

}  /* namespace */

REGISTER_SERVICE(Pxa27xQuickCapture);
