#include "../peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../cpu/emulated_memory.h"
#include "../peripheral_dispatcher.h"

namespace {

/* Intel 28F320C3 StrataFlash CFI state machine (iPaq H3xxx, SA-1110
   nCS0). Array-mode reads delegate to backed Flash via EmulatedMemory
   because cache-attr routing in ArmMmu sends only uncached accesses
   here; cached ROM reads bypass to the backed region. */

class Intel28F320C3 : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        if (!bd) return false;
        const auto b = bd->GetBoard();
        return b == Board::Ipaq3650;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x00000000u; }
    uint32_t MmioSize() const override { return 0x02000000u; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint16_t ReadHalf (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    /* Intel CFI command set (subset documented for Advanced+ Boot
       Block family). 28F320C3 Datasheet (Intel order 290645). */
    enum Mode : uint8_t {
        kReadArray  = 0xFF,
        kReadId     = 0x90,
        kReadStatus = 0x70,
        kCfiQuery   = 0x98,
        kProgram    = 0x40,  /* word program setup */
        kErase      = 0x20,  /* block erase setup, confirm with 0xD0 */
    };

    Mode    mode_   = kReadArray;
    uint8_t status_ = 0x80;   /* SR.7 = WSMS ready */

    uint8_t IdByteAt(uint32_t pa) const {
        /* Intel CFI Read ID: word 0 = Mfr (Intel = 0x0089),
           word 1 = Device (28F320C3B = 0x88C5). At byte addresses
           within any block: 0=Mfr-lo, 1=Mfr-hi, 2=Dev-lo, 3=Dev-hi. */
        const uint32_t off = pa & 0x1Fu;
        switch (off) {
            case 0: return 0x89;
            case 1: return 0x00;
            case 2: return 0xC5;
            case 3: return 0x88;
            default: return 0;
        }
    }

    uint8_t ArrayByteAt(uint32_t pa) {
        uint8_t* host = emu_.Get<EmulatedMemory>().TryTranslate(pa);
        return host ? *host : 0xFFu;
    }
};

uint8_t Intel28F320C3::ReadByte(uint32_t addr) {
    switch (mode_) {
        case kReadArray:  return ArrayByteAt(addr);
        case kReadId:     return IdByteAt(addr);
        case kReadStatus: return status_;
        case kCfiQuery:
        case kProgram:
        case kErase:
        default:          return status_;
    }
}

uint16_t Intel28F320C3::ReadHalf(uint32_t addr) {
    return static_cast<uint16_t>(ReadByte(addr)) |
           (static_cast<uint16_t>(ReadByte(addr + 1)) << 8);
}

uint32_t Intel28F320C3::ReadWord(uint32_t addr) {
    return static_cast<uint32_t>(ReadByte(addr))           |
           (static_cast<uint32_t>(ReadByte(addr + 1)) << 8 ) |
           (static_cast<uint32_t>(ReadByte(addr + 2)) << 16) |
           (static_cast<uint32_t>(ReadByte(addr + 3)) << 24);
}

void Intel28F320C3::WriteByte(uint32_t /*addr*/, uint8_t value) {
    /* §Table 5: default branch must end in ReadStatus so program/
       erase writes complete with SR.7=1, else the kernel's
       "poll until ready" loop spins forever. */
    switch (value) {
        case 0xFF:  mode_ = kReadArray;  break;
        case 0x90:  mode_ = kReadId;     break;
        case 0x70:  mode_ = kReadStatus; break;
        case 0x50:  status_ = 0x80;      break;   /* clear status, ready */
        case 0x98:  mode_ = kCfiQuery;   break;
        case 0x40:
        case 0x10:  mode_ = kProgram;    break;
        case 0x20:  mode_ = kErase;      break;
        case 0xD0:                                /* confirm — no-op data side */
        case 0xB0:                                /* suspend */
            mode_ = kReadStatus;
            break;
        default:
            /* In Program / Erase mode, this byte is the data word
               or erase confirm — silently drop (no Flash persistence
               in CERF) and report ready. */
            mode_ = kReadStatus;
            break;
    }
}

void Intel28F320C3::WriteHalf(uint32_t addr, uint16_t value) {
    WriteByte(addr, static_cast<uint8_t>(value & 0xFFu));
}

void Intel28F320C3::WriteWord(uint32_t addr, uint32_t value) {
    WriteByte(addr, static_cast<uint8_t>(value & 0xFFu));
}

}  /* namespace */

REGISTER_SERVICE(Intel28F320C3);
