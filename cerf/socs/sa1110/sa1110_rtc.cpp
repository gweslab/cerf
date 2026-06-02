#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

namespace {

/* SA-1110 Dev Man §9.3: +0x0 RTAR, +0x4 RCNR (32-bit R/W); +0x8
   RTTR R/W mask 0x03FFFFFF (15:0 divider | 25:16 trim, 31:26
   reserved); +0x10 RTSR bits 1,0 (HZ/AL) W1C, bits 3,2 (HZE/ALE)
   R/W interrupt enables. */

class Sa1110Rtc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::SA1110;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x90010000u; }
    uint32_t MmioSize() const override { return 0x00010000u; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    /* §9.3 reset states: RCNR / RTAR / RTTR are uninitialized after
       hardware reset ("undefined after nRESET"); RTSR HZE/ALE = 0,
       HZ/AL = unknown. CERF picks 0 for the unknown bits — guest
       code clears the W1C bits before relying on them. */
    uint32_t rtar_ = 0;
    uint32_t rcnr_ = 0;
    uint32_t rttr_ = 0;
    uint32_t rtsr_ = 0;

    static constexpr uint32_t kRttrMask = 0x03FFFFFFu;  /* bits 25:0 */
    static constexpr uint32_t kRtsrMask = 0x0000000Fu;  /* bits  3:0 */

    uint32_t ReadReg(uint32_t off) const;
    void     WriteReg(uint32_t off, uint32_t value);
};

uint32_t Sa1110Rtc::ReadReg(uint32_t off) const {
    switch (off) {
        case 0x00: return rtar_;
        case 0x04: return rcnr_;
        case 0x08: return rttr_ & kRttrMask;
        case 0x10: return rtsr_ & kRtsrMask;
        default:   return 0;  /* handled by caller via halt. */
    }
}

void Sa1110Rtc::WriteReg(uint32_t off, uint32_t value) {
    switch (off) {
        case 0x00: rtar_ = value; break;
        case 0x04: rcnr_ = value; break;
        case 0x08: rttr_ = value & kRttrMask; break;
        case 0x10:
            /* RTSR §9.3.3: HZE/ALE (bits 3,2) are plain R/W; HZ/AL
               (bits 1,0) are W1C. Reserved 31:4 ignored on write. */
            rtsr_ = (rtsr_ & ~(value & 0x3u))          /* W1C clear */
                  | (rtsr_ & 0xCu & ~0xCu)             /* (clear current enables) */
                  | (value & 0xCu);                    /* (set new enables) */
            rtsr_ &= kRtsrMask;
            break;
        default: break;
    }
}

uint8_t Sa1110Rtc::ReadByte(uint32_t addr) {
    const uint32_t off  = addr - MmioBase();
    const uint32_t base = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (base == 0x00 || base == 0x04 || base == 0x08 || base == 0x10) {
        return static_cast<uint8_t>((ReadReg(base) >> shift) & 0xFFu);
    }
    HaltUnsupportedAccess("ReadByte", addr, 0);
}

uint32_t Sa1110Rtc::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off == 0x00 || off == 0x04 || off == 0x08 || off == 0x10) {
        return ReadReg(off);
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Sa1110Rtc::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (base != 0x00 && base != 0x04 && base != 0x08 && base != 0x10) {
        HaltUnsupportedAccess("WriteByte", addr, value);
    }
    const uint32_t cur     = ReadReg(base);
    const uint32_t cleared = cur & ~(0xFFu << shift);
    const uint32_t merged  = cleared | (static_cast<uint32_t>(value) << shift);
    WriteReg(base, merged);
}

void Sa1110Rtc::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off == 0x00 || off == 0x04 || off == 0x08 || off == 0x10) {
        WriteReg(off, value);
        return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

}  /* namespace */

REGISTER_SERVICE(Sa1110Rtc);
