#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>
#include <vector>

namespace {

constexpr uint32_t kNorBase = 0xA0000000u;
constexpr uint32_t kNorSize = 0x00200000u;

/* S29AL016J Table 13 note 27 (PDF p30): "Address bits A19..A11 are
   don't cares for unlock and command cycles." Chip A10..A0 are the
   11 bits the FSM compares. */
constexpr uint32_t kCmdWordMask  = 0x7FFu;
/* S29AL016J Table 13 (PDF p30) Word-mode command-cycle word addrs. */
constexpr uint32_t kUnlock1Word  = 0x555u;
constexpr uint32_t kUnlock2Word  = 0x2AAu;
constexpr uint32_t kCfiQueryWord = 0x55u;

/* S29AL016J Table 13 (PDF p30) Word-mode command data values. */
constexpr uint16_t kCmdReset       = 0xF0u;
constexpr uint16_t kCmdAutoSelect  = 0x90u;
constexpr uint16_t kCmdCfiQuery    = 0x98u;
constexpr uint16_t kCmdProgram     = 0xA0u;
constexpr uint16_t kCmdEraseSetup  = 0x80u;
constexpr uint16_t kCmdSectorErase = 0x30u;
constexpr uint16_t kCmdChipErase   = 0x10u;
constexpr uint16_t kUnlockData1    = 0xAAu;
constexpr uint16_t kUnlockData2    = 0x55u;

/* nk.exe sub_88245EC0 rejects the chip for any (v34,v35,v37,v36)
   tuple other than (0x01, 0x227E, 0x2200, 0x2230|0x2231); changing
   these values fails size detection and kernel halts. */
constexpr uint16_t kIdManufacturer = 0x0001u;
constexpr uint16_t kIdDeviceBase   = 0x227Eu;
constexpr uint16_t kIdDeviceExt1   = 0x2231u;
constexpr uint16_t kIdDeviceExt2   = 0x2200u;

/* Verbatim from S29AL016J Tables 9-11 (PDF p23-24): CFI Query ID
   string, System Interface, Device Geometry. Indexed by word offset
   minus 0x10. Wrong values fail the kernel's CFI parse and halt. */
constexpr uint16_t kCfiTable[] = {
    0x0051u, 0x0052u, 0x0059u,
    0x0002u, 0x0000u,
    0x0040u, 0x0000u,
    0x0000u, 0x0000u,
    0x0000u, 0x0000u,
    0x0027u,
    0x0036u,
    0x0000u,
    0x0000u,
    0x0003u,
    0x0000u,
    0x0009u,
    0x0000u,
    0x0005u,
    0x0000u,
    0x0004u,
    0x0000u,
    0x0015u,
    0x0002u, 0x0000u,
    0x0000u, 0x0000u,
    0x0004u,
    0x0000u, 0x0000u, 0x0040u, 0x0000u,
    0x0001u, 0x0000u, 0x0020u, 0x0000u,
    0x0000u, 0x0000u, 0x0080u, 0x0000u,
    0x001Eu, 0x0000u, 0x0000u, 0x0001u,
};

/* Verbatim from S29AL016J Table 12 (PDF p24): Primary Vendor-Specific
   Extended Query. Indexed by word offset minus 0x40. */
constexpr uint16_t kCfiExtTable[] = {
    0x0050u, 0x0052u, 0x0049u,
    0x0031u,
    0x0033u,
    0x000Cu,
    0x0002u,
    0x0001u,
    0x0001u,
    0x0004u,
    0x0000u,
    0x0000u,
    0x0000u,
    0x0000u,
    0x0000u,
    0x0002u,
    0x0000u,
};

struct SectorRegion {
    uint32_t start_off;
    uint32_t end_off;
    uint32_t sector_size;
};

/* S29AL016J Bottom Boot per Table 8 (PDF p17) and Table 11 (PDF p23):
   SA0=16KB, SA1+SA2=2x8KB, SA3=32KB, SA4..SA34=31x64KB. Wrong sizes
   make EraseSector zero the wrong byte range. */
constexpr SectorRegion kSectorMap[] = {
    { 0x000000u, 0x003FFFu, 16u  * 1024u },
    { 0x004000u, 0x005FFFu,  8u  * 1024u },
    { 0x006000u, 0x007FFFu,  8u  * 1024u },
    { 0x008000u, 0x00FFFFu, 32u  * 1024u },
    { 0x010000u, 0x1FFFFFu, 64u  * 1024u },
};

uint32_t SectorBaseFromOffset(uint32_t off) {
    for (const auto& r : kSectorMap) {
        if (off >= r.start_off && off <= r.end_off) {
            return (off - r.start_off) / r.sector_size * r.sector_size + r.start_off;
        }
    }
    return 0u;
}

uint32_t SectorSizeFromOffset(uint32_t off) {
    for (const auto& r : kSectorMap) {
        if (off >= r.start_off && off <= r.end_off) return r.sector_size;
    }
    return 0u;
}

enum class Mode { ReadArray, AutoSelect, CfiQuery };
enum class Stage { Idle, Unlock1, Unlock2,
                   ProgramWait,
                   EraseUnlock1, EraseUnlock2, EraseConfirm };

class SpansionS29AL016J : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::ZuneKeel;
    }

    void OnReady() override {
        backing_.assign(kNorSize, 0xFFu);
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kNorBase; }
    uint32_t MmioSize() const override { return kNorSize; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint16_t ReadHalf (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    uint16_t AutoSelectAt(uint32_t word_off) const;
    uint16_t CfiAt(uint32_t word_off) const;
    void     HandleHalfCommand(uint32_t off, uint16_t value);
    void     ProgramWord(uint32_t off, uint16_t value);
    void     EraseSector(uint32_t off);
    void     EraseChip();

    std::vector<uint8_t> backing_;
    Mode  mode_  = Mode::ReadArray;
    Stage stage_ = Stage::Idle;
};

uint16_t SpansionS29AL016J::AutoSelectAt(uint32_t word_off) const {
    switch (word_off & 0xFFu) {
    case 0x00u: return kIdManufacturer;
    case 0x01u: return kIdDeviceBase;
    case 0x02u: return 0x0000u;
    case 0x03u: return 0x0014u;
    case 0x0Eu: return kIdDeviceExt1;
    case 0x0Fu: return kIdDeviceExt2;
    default:    return 0xFFFFu;
    }
}

uint16_t SpansionS29AL016J::CfiAt(uint32_t word_off) const {
    if (word_off >= 0x10u && word_off < 0x10u + sizeof(kCfiTable)/sizeof(kCfiTable[0])) {
        return kCfiTable[word_off - 0x10u];
    }
    if (word_off >= 0x40u && word_off < 0x40u + sizeof(kCfiExtTable)/sizeof(kCfiExtTable[0])) {
        return kCfiExtTable[word_off - 0x40u];
    }
    return 0xFFFFu;
}

uint8_t SpansionS29AL016J::ReadByte(uint32_t addr) {
    const uint32_t off  = addr - kNorBase;
    const uint32_t word = off >> 1;
    const uint32_t shift = (off & 1u) * 8u;
    if (mode_ == Mode::ReadArray) {
        return off < kNorSize ? backing_[off] : 0xFFu;
    }
    uint16_t v = (mode_ == Mode::AutoSelect) ? AutoSelectAt(word) : CfiAt(word);
    return static_cast<uint8_t>((v >> shift) & 0xFFu);
}

uint16_t SpansionS29AL016J::ReadHalf(uint32_t addr) {
    const uint32_t off  = addr - kNorBase;
    const uint32_t word = off >> 1;
    if (mode_ == Mode::ReadArray) {
        if (off + 1 >= kNorSize) return 0xFFFFu;
        return static_cast<uint16_t>(backing_[off]) |
               (static_cast<uint16_t>(backing_[off + 1]) << 8);
    }
    return (mode_ == Mode::AutoSelect) ? AutoSelectAt(word) : CfiAt(word);
}

uint32_t SpansionS29AL016J::ReadWord(uint32_t addr) {
    /* Zune Keel: 32-bit bus, 4 MMIO bytes per chip word, low byte
       replicated. Stride==2 breaks kernel sub_88245EC0 CFI sig read
       at byte 0x40 (expects 0x51515151 from chip word 0x10). */
    const uint32_t off       = addr - kNorBase;
    const uint32_t chip_word = off >> 2;
    uint16_t v;
    if (mode_ == Mode::ReadArray) {
        const uint32_t byte_off = chip_word * 2;
        if (byte_off + 1 >= kNorSize) return 0xFFFFFFFFu;
        v = static_cast<uint16_t>(backing_[byte_off]) |
            (static_cast<uint16_t>(backing_[byte_off + 1]) << 8);
    } else {
        v = (mode_ == Mode::AutoSelect) ? AutoSelectAt(chip_word) : CfiAt(chip_word);
    }
    const uint8_t low_byte = static_cast<uint8_t>(v & 0xFFu);
    return 0x01010101u * static_cast<uint32_t>(low_byte);
}

void SpansionS29AL016J::WriteByte(uint32_t addr, uint8_t value) {
    LOG(Periph, "[S29AL016J] WriteByte off=0x%05X val=0x%02X — S29AL016J "
                "Table 13 lists only word-mode and byte-mode bus cycles "
                "(BYTE# pin), not partial-byte writes on a x16 bus\n",
        addr - kNorBase, value);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

void SpansionS29AL016J::WriteHalf(uint32_t addr, uint16_t value) {
    HandleHalfCommand(addr - kNorBase, value & 0xFFu);
}

void SpansionS29AL016J::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off      = addr - kNorBase;
    const uint32_t half_off = off >> 1;
    HandleHalfCommand(half_off, static_cast<uint16_t>(value & 0xFFu));
}

void SpansionS29AL016J::HandleHalfCommand(uint32_t off, uint16_t cmd) {
    if (cmd == kCmdReset) {
        mode_  = Mode::ReadArray;
        stage_ = Stage::Idle;
        return;
    }

    const uint32_t word = (off >> 1) & kCmdWordMask;

    if (stage_ == Stage::Idle) {
        /* kernel sub_88245EC0 writes 0x98 at chip-word 0x555 (not
           0x55); strict word-match per datasheet line 3794 halts. */
        if (cmd == kCmdCfiQuery) {
            mode_ = Mode::CfiQuery;
            return;
        }
        if (word == kUnlock1Word && cmd == kUnlockData1) {
            stage_ = Stage::Unlock1;
            return;
        }
        LOG(Periph, "[S29AL016J] unexpected Idle write off=0x%05X word=0x%03X "
                    "cmd=0x%02X (expected reset 0xF0 any addr, unlock-1 word=0x555 "
                    "val=0xAA, or CFI 0x98 any addr)\n",
            off, word, cmd);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        return;
    }

    if (stage_ == Stage::Unlock1) {
        if (word == kUnlock2Word && cmd == kUnlockData2) {
            stage_ = Stage::Unlock2;
            return;
        }
        LOG(Periph, "[S29AL016J] Unlock1 expected word=0x2AA val=0x55, "
                    "got off=0x%05X word=0x%03X cmd=0x%02X\n", off, word, cmd);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        return;
    }

    if (stage_ == Stage::Unlock2) {
        if (word == kUnlock1Word) {
            switch (cmd) {
            case kCmdAutoSelect:
                mode_  = Mode::AutoSelect;
                stage_ = Stage::Idle;
                return;
            case kCmdCfiQuery:
                mode_  = Mode::CfiQuery;
                stage_ = Stage::Idle;
                return;
            case kCmdProgram:
                stage_ = Stage::ProgramWait;
                return;
            case kCmdEraseSetup:
                stage_ = Stage::EraseUnlock1;
                return;
            }
        }
        LOG(Periph, "[S29AL016J] Unlock2 expected cmd cycle at word=0x555, "
                    "got off=0x%05X word=0x%03X cmd=0x%02X\n", off, word, cmd);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        return;
    }

    if (stage_ == Stage::ProgramWait) {
        ProgramWord(off, cmd);
        stage_ = Stage::Idle;
        mode_  = Mode::ReadArray;
        return;
    }

    if (stage_ == Stage::EraseUnlock1) {
        if (word == kUnlock1Word && cmd == kUnlockData1) {
            stage_ = Stage::EraseUnlock2;
            return;
        }
        LOG(Periph, "[S29AL016J] EraseUnlock1 expected word=0x555 val=0xAA, "
                    "got off=0x%05X word=0x%03X cmd=0x%02X\n", off, word, cmd);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        return;
    }

    if (stage_ == Stage::EraseUnlock2) {
        if (word == kUnlock2Word && cmd == kUnlockData2) {
            stage_ = Stage::EraseConfirm;
            return;
        }
        LOG(Periph, "[S29AL016J] EraseUnlock2 expected word=0x2AA val=0x55, "
                    "got off=0x%05X word=0x%03X cmd=0x%02X\n", off, word, cmd);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        return;
    }

    if (stage_ == Stage::EraseConfirm) {
        if (word == kUnlock1Word && cmd == kCmdChipErase) {
            EraseChip();
            stage_ = Stage::Idle;
            mode_  = Mode::ReadArray;
            return;
        }
        if (cmd == kCmdSectorErase) {
            EraseSector(off);
            stage_ = Stage::Idle;
            mode_  = Mode::ReadArray;
            return;
        }
        LOG(Periph, "[S29AL016J] EraseConfirm expected chip-erase 0x10 at "
                    "word=0x555 or sector-erase 0x30 at sector word, got "
                    "off=0x%05X word=0x%03X cmd=0x%02X\n", off, word, cmd);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
}

void SpansionS29AL016J::ProgramWord(uint32_t off, uint16_t value) {
    if (off + 1 >= kNorSize) return;
    backing_[off    ] &= static_cast<uint8_t>(value & 0xFFu);
    backing_[off + 1] &= static_cast<uint8_t>((value >> 8) & 0xFFu);
}

void SpansionS29AL016J::EraseSector(uint32_t off) {
    const uint32_t base = SectorBaseFromOffset(off);
    const uint32_t size = SectorSizeFromOffset(off);
    if (size == 0u || base + size > kNorSize) return;
    for (uint32_t i = 0; i < size; ++i) backing_[base + i] = 0xFFu;
}

void SpansionS29AL016J::EraseChip() {
    for (uint32_t i = 0; i < kNorSize; ++i) backing_[i] = 0xFFu;
}

}  /* namespace */

REGISTER_SERVICE(SpansionS29AL016J);
