#include "../peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../peripheral_dispatcher.h"

#include <cstdint>
#include <cstring>
#include <vector>

namespace {

/* MediaQ MQ-1100/1132 (MQ1188), Falcon CS2. §4.2 / Figure 4-1: 512 KB
   aperture = 256 KB frame-buffer SRAM, then 8 KB registers at 0x40000, then
   248 KB SRAM for non-graphics (USB/audio) buffers. Both SRAM regions are
   plain RAM; only the register window has device semantics (GC/display regs
   HaltUnsupported so the display first-hit is loud, task §6). */
class MediaQMq1188 : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::FalconPC3xx;
    }
    void OnReady() override {
        sram_.assign(kApertureSize, 0u);
        regs_[0x384u / 4u] = 0xF0000000u;  /* DC01R reset (Table 4-2). */
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x08000000u; }
    uint32_t MmioSize() const override { return kApertureSize; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint16_t ReadHalf (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    static constexpr uint32_t kApertureSize = 0x00080000u;  /* 512 KB total. */
    static constexpr uint32_t kRegBase      = 0x00040000u;  /* registers start. */
    static constexpr uint32_t kRegWindow    = 0x00002000u;  /* 8 KB register space. */

    static constexpr uint32_t kGcLo = 0x180u;  /* Graphics Controller — display. */
    static constexpr uint32_t kGcHi = 0x1FFu;
    static constexpr uint32_t kChipRegsEnd = 0x3FFu;

    /* Table 4-1: USB Host = 0x500..0x5FF, an OHCI controller. Careful stub —
       HcRevision must read OHCI 1.0a and HcCommandStatus.HCR must self-clear
       or the driver hangs polling reset-complete; all else is zero-default
       storage (reads as no-device / no-interrupt). */
    static constexpr uint32_t kUsbLo  = 0x500u;
    static constexpr uint32_t kUsbHi  = 0x5FFu;
    static constexpr uint32_t kHcRevision      = 0x00u;  /* OHCI op-reg offsets. */
    static constexpr uint32_t kHcCommandStatus = 0x08u;
    static constexpr uint32_t kHcrResetBit     = 0x1u;   /* HcCommandStatus.HCR. */

    static bool InRegWindow(uint32_t off) {
        return off >= kRegBase && off < kRegBase + kRegWindow;
    }
    static bool IsDisplayModule(uint32_t roff) { return roff >= kGcLo && roff <= kGcHi; }
    static bool IsUsbHost(uint32_t roff) { return roff >= kUsbLo && roff <= kUsbHi; }

    uint32_t RegRead(uint32_t addr);
    void     RegWrite(uint32_t addr, uint32_t value);

    std::vector<uint8_t> sram_;
    uint32_t regs_[(kChipRegsEnd / 4u) + 1u] = {};
    uint32_t usbhost_[(kUsbHi - kUsbLo) / 4u + 1u] = {};
};

uint32_t MediaQMq1188::RegRead(uint32_t addr) {
    const uint32_t roff = (addr - MmioBase()) - kRegBase;
    if (IsDisplayModule(roff)) HaltUnsupportedAccess("ReadWord(GC/display)", addr, 0);
    if (IsUsbHost(roff)) {
        const uint32_t uoff = roff - kUsbLo;
        if (uoff == kHcRevision)      return 0x10u;  /* OHCI 1.0a. */
        if (uoff == kHcCommandStatus) return usbhost_[uoff / 4u] & ~kHcrResetBit;
        return usbhost_[uoff / 4u];
    }
    if (roff <= kChipRegsEnd && (roff & 3u) == 0u) return regs_[roff / 4u];
    HaltUnsupportedAccess("ReadWord(reg)", addr, 0);
}

void MediaQMq1188::RegWrite(uint32_t addr, uint32_t value) {
    const uint32_t roff = (addr - MmioBase()) - kRegBase;
    if (IsDisplayModule(roff)) HaltUnsupportedAccess("WriteWord(GC/display)", addr, value);
    if (IsUsbHost(roff)) { usbhost_[(roff - kUsbLo) / 4u] = value; return; }
    if (roff <= kChipRegsEnd && (roff & 3u) == 0u) { regs_[roff / 4u] = value; return; }
    HaltUnsupportedAccess("WriteWord(reg)", addr, value);
}

uint8_t MediaQMq1188::ReadByte(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (InRegWindow(off)) {
        const uint32_t word = RegRead((addr & ~0x3u));
        return static_cast<uint8_t>(word >> ((off & 0x3u) * 8u));
    }
    return sram_[off];
}

uint16_t MediaQMq1188::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (InRegWindow(off)) {
        const uint32_t word = RegRead((addr & ~0x3u));
        return static_cast<uint16_t>(word >> ((off & 0x2u) * 8u));
    }
    uint16_t v;
    std::memcpy(&v, &sram_[off], sizeof(v));
    return v;
}

uint32_t MediaQMq1188::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (InRegWindow(off)) return RegRead(addr);
    uint32_t v;
    std::memcpy(&v, &sram_[off], sizeof(v));
    return v;
}

void MediaQMq1188::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = addr - MmioBase();
    if (InRegWindow(off)) {
        const uint32_t shift = (off & 0x3u) * 8u;
        const uint32_t word  = RegRead(addr & ~0x3u);
        RegWrite(addr & ~0x3u, (word & ~(0xFFu << shift)) | (static_cast<uint32_t>(value) << shift));
        return;
    }
    sram_[off] = value;
}

void MediaQMq1188::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - MmioBase();
    if (InRegWindow(off)) {
        const uint32_t shift = (off & 0x2u) * 8u;
        const uint32_t word  = RegRead(addr & ~0x3u);
        RegWrite(addr & ~0x3u, (word & ~(0xFFFFu << shift)) | (static_cast<uint32_t>(value) << shift));
        return;
    }
    std::memcpy(&sram_[off], &value, sizeof(value));
}

void MediaQMq1188::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (InRegWindow(off)) { RegWrite(addr, value); return; }
    std::memcpy(&sram_[off], &value, sizeof(value));
}

}  /* namespace */

REGISTER_SERVICE(MediaQMq1188);
