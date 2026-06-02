#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/host_widget.h"
#include "../../host/host_widget_registry.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kBase = 0x00000000u;
constexpr uint32_t kSize = 0x06000000u;  /* 96 MB, matches OAT NOR bank */

/* AMD JEDEC command FSM states, all 16-bit-doubled forms. */
constexpr uint16_t kCmdReset      = 0xF0F0u;   /* AMD_CMD_RESET             */
constexpr uint16_t kCmdAutoSel    = 0x9090u;   /* AMD_CMD_AUTOSEL           */
constexpr uint16_t kCmdProgram    = 0xA0A0u;   /* AMD_CMD_PROGRAM           */
constexpr uint16_t kCmdUnlock1    = 0xAAAAu;   /* after first  0xAA@0xAAA   */
constexpr uint16_t kCmdUnlock1Era = 0xAAABu;   /* after first  0xAA@0xAAA
                                                  during erase setup       */
constexpr uint16_t kCmdSectErase  = 0x8080u;   /* AMD_CMD_SECTERASE         */
constexpr uint16_t kCmdSectEraseConfirm = 0x3030u; /* AMD_CMD_SECTERASE_CONFIRM */
constexpr uint16_t kUnlockData1   = 0xAAAAu;   /* unlock cycle 1 data       */
constexpr uint16_t kUnlockData2   = 0x5555u;   /* unlock cycle 2 data       */

/* AMD addresses, 16-bit-bus byte-addressed (word << 1). */
constexpr uint32_t kUnlockAddr1   = 0x5555u << 1;  /* 0xAAAA */
constexpr uint32_t kUnlockAddr2   = 0x2AAAu << 1;  /* 0x5554 */

/* Autoselect identity:
     word[0] bytes 0..1: manufacturer code 0x01 (AMD)
     word[0] bytes 2..3: device code 0x225b (AM29LV800BB) */
constexpr uint32_t kAutoSelIdent  = 0x225B0001u;

/* AM29LV800BB sector geometry — bottom-boot organisation:
   16 KB boot block, two 8 KB blocks, one 32 KB block, then uniform
   64 KB sectors. */
size_t SectorSizeFromAddress(uint32_t io_addr) {
    if (io_addr < 16u * 1024u) return 16u * 1024u;
    if (io_addr < 24u * 1024u) return  8u * 1024u;
    if (io_addr < 32u * 1024u) return  8u * 1024u;
    if (io_addr < 64u * 1024u) return 32u * 1024u;
    return 64u * 1024u;
}

class Am29Lv800Bb : public Peripheral, public HostWidget {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        if (!bd) return false;
        const auto b = bd->GetBoard();
        return b == Board::Smdk2410DevEmu;
    }
    void OnReady() override {
        (void)emu_.Get<EmulatedMemory>().Translate(kBase);
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<HostWidgetRegistry>().Register(this);
        LOG(Boot, "Am29Lv800Bb: AM29LV800BB at PA 0x%08X size 0x%X "
                  "(96 MB, EmulatedMemory-backed; FSM-write only)\n",
                  kBase, kSize);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    /* HostWidget. Reads bypass this peripheral (JIT TLB fast-path straight to
       EmulatedMemory), so only writes (the FSM command/program/erase cycles)
       are observable here — TX-only activity. */
    std::wstring WidgetName() const override { return L"NOR Flash"; }
    WidgetGroup  Group() const override { return WidgetGroup::Storage; }
    std::wstring Tooltip() const override { return L"NOR Flash — AMD AM29LV800BB"; }
    std::vector<WidgetMenuItem> BuildMenu() override {
        WidgetMenuItem hdr;
        hdr.label   = L"AM29LV800BB (8 Mbit NOR)";
        hdr.enabled = false;
        return { std::move(hdr) };
    }
    void DrawIcon(HDC dc, const RECT& box) const override;

    uint8_t  ReadByte (uint32_t addr) override {
        return emu_.Get<EmulatedMemory>().ReadByte(addr);
    }
    uint16_t ReadHalf (uint32_t addr) override {
        return emu_.Get<EmulatedMemory>().ReadHalf(addr);
    }
    uint32_t ReadWord (uint32_t addr) override {
        return emu_.Get<EmulatedMemory>().ReadWord(addr);
    }

    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    void DoWriteHalf(uint32_t io_addr, uint16_t value);

    uint16_t cmd_          = kCmdReset;
    uint32_t cached_word0_ = 0u;  /* saved during autoselect */
};

void Am29Lv800Bb::WriteByte(uint32_t addr, uint8_t value) {
    HaltUnsupportedAccess("WriteByte", addr, value);
}
void Am29Lv800Bb::WriteHalf(uint32_t addr, uint16_t value) {
    MarkTx();
    DoWriteHalf(addr - kBase, value);
}

void Am29Lv800Bb::DrawIcon(HDC dc, const RECT& box) const {
    const int cx = (box.left + box.right) / 2;
    const int cy = (box.top + box.bottom) / 2;
    RECT body = { cx - 8, cy - 6, cx + 8, cy + 6 };

    HBRUSH  fill = CreateSolidBrush(RGB(40, 44, 52));
    HPEN    pen  = CreatePen(PS_SOLID, 1, RGB(150, 150, 160));
    HGDIOBJ ob   = SelectObject(dc, fill);
    HGDIOBJ op   = SelectObject(dc, pen);
    Rectangle(dc, body.left, body.top, body.right, body.bottom);
    for (int i = -1; i <= 1; ++i) {
        const int px = cx + i * 5;
        MoveToEx(dc, px, body.top - 2, nullptr);    LineTo(dc, px, body.top);
        MoveToEx(dc, px, body.bottom - 1, nullptr); LineTo(dc, px, body.bottom + 1);
    }
    SelectObject(dc, ob);
    SelectObject(dc, op);
    DeleteObject(fill);
    DeleteObject(pen);
}
void Am29Lv800Bb::WriteWord(uint32_t addr, uint32_t value) {
    /* 32-bit writes are two 16-bit AMD bus cycles. Real hardware
       would see them sequentially. The CE driver does WriteHalf
       only and never exercises this path. Halt to surface if it
       ever fires. */
    HaltUnsupportedAccess("WriteWord", addr, value);
}

/* AMD JEDEC command FSM implementation. All flash-byte mutations go
   through EmulatedMemory so subsequent reads (which bypass this
   peripheral and read EmulatedMemory directly via the JIT's TLB
   fast-path) observe the FSM's effects. */
void Am29Lv800Bb::DoWriteHalf(uint32_t io_addr, uint16_t value) {
    auto& mem = emu_.Get<EmulatedMemory>();
    switch (io_addr) {
    case kUnlockAddr1: /* AMD_CMD_ADDR and AMD_UNLOCK_ADDR1 */
        /* Check if we are currently in the middle of a write. */
        if (cmd_ != kCmdProgram) {
            /* Transitioning from AutoSelect state into Read/Idle state. */
            if (value == kCmdReset && cmd_ == kCmdAutoSel) {
                /* Restore the actual value of the word we replaced
                   with Manufacturer/Device ID. */
                mem.WriteWord(kBase, cached_word0_);
            }
            /* Transitioning from AMD_UNLOCK_ADDR2 into AutoSelect state. */
            if (value == kCmdAutoSel && cmd_ == kCmdUnlock1) {
                cached_word0_ = mem.ReadWord(kBase);
                mem.WriteWord(kBase, kAutoSelIdent);
            }
            /* Transitioning from AMD_CMD_SECTERASE into AMD_UNLOCK_ADDR1_ERASE. */
            if (value == kCmdUnlock1 && cmd_ == kCmdSectErase) {
                cmd_ = kCmdUnlock1Era;
            } else {
                cmd_ = value;
            }
            return;
        }
        /* fall through if cmd_ == kCmdProgram */
        [[fallthrough]];
    default:
        /* The behavior of the write depends on the currently-selected
           command. */
        switch (cmd_) {
        case kCmdReset:
            /* writes after a reset are ignored */
            break;
        case kCmdAutoSel:
            /* writes after an autosel are ignored */
            break;
        case kCmdProgram:
            /* Write after AMD_CMD_PROGRAM stores the value into flash
               memory. */
            mem.WriteHalf(kBase + io_addr, value);
            cmd_ = kCmdReset;
            break;
        case kCmdUnlock1:
            /* AMD_CMD_UNLOCK1 to AMD_UNLOCK_UNLOCK2 transition. */
            if (value != kUnlockData2 || io_addr != kUnlockAddr2) {
                LOG(Caution, "Am29Lv800Bb unlock1 mismatch: "
                             "io_addr=0x%X value=0x%04X (expected "
                             "addr=0x%X value=0x%04X)\n",
                    io_addr, value, kUnlockAddr2, kUnlockData2);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            break;
        case kCmdUnlock1Era:
            /* AMD_CMD_UNLOCK1_ERASE to AMD_UNLOCK_UNLOCK2_ERASE transition. */
            if (value != kUnlockData2 || io_addr != kUnlockAddr2) {
                LOG(Caution, "Am29Lv800Bb unlock1-erase mismatch: "
                             "io_addr=0x%X value=0x%04X (expected "
                             "addr=0x%X value=0x%04X)\n",
                    io_addr, value, kUnlockAddr2, kUnlockData2);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            cmd_ = kCmdSectErase;
            break;
        case kCmdSectErase:
            /* Write after SECTERASE contains the value
               AMD_CMD_SECTERASE_CONFIRM; address is the sector to
               erase. */
            if (value == kCmdSectEraseConfirm) {
                const size_t sz = SectorSizeFromAddress(io_addr);
                std::memset(mem.Translate(kBase + io_addr), 0xFF, sz);
            }
            cmd_ = kCmdReset;
            break;
        default:
            LOG(Caution, "Am29Lv800Bb unsupported FSM state: "
                         "cmd=0x%04X io_addr=0x%X value=0x%04X\n",
                cmd_, io_addr, value);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        break;
    }
}

}  /* namespace */

REGISTER_SERVICE(Am29Lv800Bb);
