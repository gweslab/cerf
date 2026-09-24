#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "sa11xx_ssp_device.h"

namespace {

/* SA-1110 §11.12.14 SSP: SSCR0 +0x60, SSCR1 +0x64, SSDR +0x6C,
   SSSR +0x74 (TNF=1 reset; ROR is W1C, others R-O). TNF MUST stay
   set or guest TX writes block forever polling SSSR.TNF. */

class Sa11xxSsp : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
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

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    uint32_t sscr0_ = 0;
    uint32_t sscr1_ = 0;
    uint32_t ssdr_  = 0;
    uint32_t sssr_  = 0x02;   /* TNF=1 reset state */

    uint32_t ReadReg(uint32_t off) {
        switch (off) {
            case 0x60: return sscr0_;
            case 0x64: return sscr1_;
            case 0x6C:
                sssr_ &= ~0x04u;           /* RX FIFO drained -> RNE clear. */
                return ssdr_;
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
        LOG(Periph, "[Sa11xxSsp] W %s (+0x%02X) = 0x%08X\n", nm, off, value);
#endif
        switch (off) {
            case 0x60: sscr0_ = value; break;
            case 0x64: sscr1_ = value; break;
            case 0x6C:
                /* Full-duplex transfer: a slave (board-registered
                   Sa11xxSspDevice) answers in the same frame; RNE (bit 2)
                   flags the response. No slave -> TX drops, RNE stays 0. */
                if (auto* dev = emu_.TryGet<Sa11xxSspDevice>()) {
                    ssdr_  = dev->Exchange(static_cast<uint16_t>(value));
                    sssr_ |= 0x04u;
                }
                break;
            case 0x74: sssr_  = (sssr_ & ~0x40u) | (sssr_ & ~(value & 0x40u));
                       break;                /* ROR (bit 6) W1C, rest R-O */
            default:   break;
        }
    }
    static bool IsKnown(uint32_t off) {
        return off == 0x60 || off == 0x64 || off == 0x6C || off == 0x74;
    }
};

uint8_t Sa11xxSsp::ReadByte(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsKnown(base)) HaltUnsupportedAccess("ReadByte", addr, 0);
    return static_cast<uint8_t>((ReadReg(base) >> shift) & 0xFFu);
}

uint32_t Sa11xxSsp::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("ReadWord", addr, 0);
    return ReadReg(off);
}

void Sa11xxSsp::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsKnown(base)) HaltUnsupportedAccess("WriteByte", addr, value);
    const uint32_t cur     = ReadReg(base);
    const uint32_t cleared = cur & ~(0xFFu << shift);
    WriteReg(base, cleared | (static_cast<uint32_t>(value) << shift));
}

void Sa11xxSsp::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("WriteWord", addr, value);
    WriteReg(off, value);
}

void Sa11xxSsp::SaveState(StateWriter& w) {
    w.Write("sscr0", sscr0_);  w.Write("sscr1", sscr1_);  w.Write("ssdr", ssdr_);  w.Write("sssr", sssr_);
}

void Sa11xxSsp::RestoreState(StateReader& r) {
    r.Read("sscr0", sscr0_);  r.Read("sscr1", sscr1_);  r.Read("ssdr", ssdr_);  r.Read("sssr", sssr_);
}

}  /* namespace */

REGISTER_SERVICE(Sa11xxSsp);
