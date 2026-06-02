#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

namespace {

/* SA-1110 §11.12.14 SSP: SSCR0 +0x60, SSCR1 +0x64, SSDR +0x6C,
   SSSR +0x74 (TNF=1 reset; ROR is W1C, others R-O). TNF MUST stay
   set or guest TX writes block forever polling SSSR.TNF. */

class Sa1110Ssp : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::SA1110;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x80070000u; }
    uint32_t MmioSize() const override { return 0x00010000u; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    uint32_t sscr0_ = 0;
    uint32_t sscr1_ = 0;
    uint32_t ssdr_  = 0;
    uint32_t sssr_  = 0x02;   /* TNF=1 reset state */

    uint32_t ReadReg(uint32_t off) const {
        switch (off) {
            case 0x60: return sscr0_;
            case 0x64: return sscr1_;
            case 0x6C: return ssdr_;
            case 0x74: return sssr_;
            default:   return 0;
        }
    }
    void WriteReg(uint32_t off, uint32_t value) {
#if CERF_DEV_MODE
        const char* nm =
            off == 0x60 ? "SSCR0" :
            off == 0x64 ? "SSCR1" :
            off == 0x6C ? "SSDR " :
            off == 0x74 ? "SSSR " : "?    ";
        LOG(Periph, "[Sa1110Ssp] W %s (+0x%02X) = 0x%08X\n", nm, off, value);
#endif
        switch (off) {
            case 0x60: sscr0_ = value; break;
            case 0x64: sscr1_ = value; break;
            case 0x6C: ssdr_  = value; break;
            case 0x74: sssr_  = (sssr_ & ~0x40u) | (sssr_ & ~(value & 0x40u));
                       break;                /* ROR (bit 6) W1C, rest R-O */
            default:   break;
        }
    }
    static bool IsKnown(uint32_t off) {
        return off == 0x60 || off == 0x64 || off == 0x6C || off == 0x74;
    }
};

uint8_t Sa1110Ssp::ReadByte(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsKnown(base)) HaltUnsupportedAccess("ReadByte", addr, 0);
    return static_cast<uint8_t>((ReadReg(base) >> shift) & 0xFFu);
}

uint32_t Sa1110Ssp::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("ReadWord", addr, 0);
    return ReadReg(off);
}

void Sa1110Ssp::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsKnown(base)) HaltUnsupportedAccess("WriteByte", addr, value);
    const uint32_t cur     = ReadReg(base);
    const uint32_t cleared = cur & ~(0xFFu << shift);
    WriteReg(base, cleared | (static_cast<uint32_t>(value) << shift));
}

void Sa1110Ssp::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("WriteWord", addr, value);
    WriteReg(off, value);
}

}  /* namespace */

REGISTER_SERVICE(Sa1110Ssp);
