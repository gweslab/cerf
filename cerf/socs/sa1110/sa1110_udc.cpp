#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

namespace {

/* SA-1110 §11.8.14: UDCCR/UDCAR/UDCOMP/UDCIMP at +0x00/04/08/0C,
   UDCCS0/1/2 at +0x10/14/18, UDCD0/UDCWC/UDCDR at +0x1C/20/28,
   UDCSR (W1C) at +0x30. With no USB host attached, UDCSR sees no
   events — kernel polls find nothing and move on. */

class Sa1110Udc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::SA1110;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x80000000u; }
    uint32_t MmioSize() const override { return 0x00010000u; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    uint32_t udccr_  = 0;
    uint32_t udcar_  = 0;
    uint32_t udcomp_ = 0;
    uint32_t udcimp_ = 0;
    uint32_t udccs0_ = 0;
    uint32_t udccs1_ = 0;
    uint32_t udccs2_ = 0;
    uint32_t udcd0_  = 0;
    uint32_t udcdr_  = 0;
    uint32_t udcsr_  = 0;

    uint32_t ReadReg(uint32_t off) const;
    void     WriteReg(uint32_t off, uint32_t value);

    static bool IsKnown(uint32_t off) {
        switch (off) {
            case 0x00: case 0x04: case 0x08: case 0x0C:
            case 0x10: case 0x14: case 0x18:
            case 0x1C: case 0x20: case 0x28: case 0x30:
                return true;
            default: return false;
        }
    }
};

uint32_t Sa1110Udc::ReadReg(uint32_t off) const {
    switch (off) {
        case 0x00: return udccr_;
        case 0x04: return udcar_;
        case 0x08: return udcomp_;
        case 0x0C: return udcimp_;
        case 0x10: return udccs0_;
        case 0x14: return udccs1_;
        case 0x18: return udccs2_;
        case 0x1C: return udcd0_;
        case 0x20: return 0;                  /* UDCWC R-O, no RX bytes */
        case 0x28: return udcdr_;
        case 0x30: return udcsr_;
        default:   return 0;
    }
}

void Sa1110Udc::WriteReg(uint32_t off, uint32_t value) {
    switch (off) {
        case 0x00: udccr_  = value; break;
        case 0x04: udcar_  = value; break;
        case 0x08: udcomp_ = value; break;
        case 0x0C: udcimp_ = value; break;
        case 0x10: udccs0_ = value; break;
        case 0x14: udccs1_ = value; break;
        case 0x18: udccs2_ = value; break;
        case 0x1C: udcd0_  = value; break;
        case 0x20: break;                     /* UDCWC R-O */
        case 0x28: udcdr_  = value; break;
        case 0x30: udcsr_ &= ~value; break;   /* W1C */
        default:   break;
    }
}

uint8_t Sa1110Udc::ReadByte(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsKnown(base)) HaltUnsupportedAccess("ReadByte", addr, 0);
    return static_cast<uint8_t>((ReadReg(base) >> shift) & 0xFFu);
}

uint32_t Sa1110Udc::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("ReadWord", addr, 0);
    return ReadReg(off);
}

void Sa1110Udc::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsKnown(base)) HaltUnsupportedAccess("WriteByte", addr, value);
    const uint32_t cur     = ReadReg(base);
    const uint32_t cleared = cur & ~(0xFFu << shift);
    WriteReg(base, cleared | (static_cast<uint32_t>(value) << shift));
}

void Sa1110Udc::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("WriteWord", addr, value);
    WriteReg(off, value);
}

}  /* namespace */

REGISTER_SERVICE(Sa1110Udc);
