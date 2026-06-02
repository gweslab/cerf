#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

namespace {

/* SA-1110 Dev Man §9.1.1: GPSR (+0x8) and GPCR (+0xC) are W-O
   set/clear commands updating the output shadow read via GPLR
   (+0x0); plain-reg storage breaks GPLR readback. GEDR (+0x18)
   is W1C. */

class Sa1110Gpio : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::SA1110;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x90040000u; }
    uint32_t MmioSize() const override { return 0x00010000u; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    static constexpr uint32_t kPinMask = 0x0FFFFFFFu;  /* bits 27:0 */

    /* Output-pin shadow (driven by GPSR/GPCR writes for output-
       configured pins). GPLR returns this OR-ed with the input-pin
       sense (input pins read 0 — no physical pins connected here
       beyond what board-side peripherals will eventually feed in). */
    uint32_t output_state_ = 0;
    uint32_t gpdr_         = 0;
    uint32_t grer_         = 0;
    uint32_t gfer_         = 0;
    uint32_t gedr_         = 0;
    uint32_t gafr_         = 0;

    uint32_t ReadGplr() const { return output_state_ & gpdr_ & kPinMask; }

    uint32_t ReadReg(uint32_t off) const;
    void     WriteReg(uint32_t off, uint32_t value);
};

uint32_t Sa1110Gpio::ReadReg(uint32_t off) const {
    switch (off) {
        case 0x00: return ReadGplr();                          /* GPLR R-O */
        case 0x04: return gpdr_ & kPinMask;                    /* GPDR R/W */
        case 0x08: return 0;                                   /* GPSR W-O, read unpredictable */
        case 0x0C: return 0;                                   /* GPCR W-O, read unpredictable */
        case 0x10: return grer_ & kPinMask;                    /* GRER R/W */
        case 0x14: return gfer_ & kPinMask;                    /* GFER R/W */
        case 0x18: return gedr_ & kPinMask;                    /* GEDR R/W (W1C) */
        case 0x1C: return gafr_ & kPinMask;                    /* GAFR R/W */
        default:   return 0;
    }
}

void Sa1110Gpio::WriteReg(uint32_t off, uint32_t value) {
    const uint32_t v = value & kPinMask;
    switch (off) {
        case 0x00: break;                                      /* GPLR R-O, writes ignored */
        case 0x04: gpdr_ = v; break;
        case 0x08: output_state_ = (output_state_ | (v & gpdr_)) & kPinMask; break;
        case 0x0C: output_state_ &= ~(v & gpdr_); break;
        case 0x10: grer_ = v; break;
        case 0x14: gfer_ = v; break;
        case 0x18: gedr_ &= ~v; break;                         /* W1C */
        case 0x1C: gafr_ = v; break;
        default:   break;
    }
}

uint8_t Sa1110Gpio::ReadByte(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (base > 0x1C) HaltUnsupportedAccess("ReadByte", addr, 0);
    return static_cast<uint8_t>((ReadReg(base) >> shift) & 0xFFu);
}

uint32_t Sa1110Gpio::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off > 0x1C || (off & 0x3u) != 0) HaltUnsupportedAccess("ReadWord", addr, 0);
    return ReadReg(off);
}

void Sa1110Gpio::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (base > 0x1C) HaltUnsupportedAccess("WriteByte", addr, value);
    const uint32_t cur     = ReadReg(base);
    const uint32_t cleared = cur & ~(0xFFu << shift);
    WriteReg(base, cleared | (static_cast<uint32_t>(value) << shift));
}

void Sa1110Gpio::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off > 0x1C || (off & 0x3u) != 0) HaltUnsupportedAccess("WriteWord", addr, value);
    WriteReg(off, value);
}

}  /* namespace */

REGISTER_SERVICE(Sa1110Gpio);
