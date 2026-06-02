#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../core/string_utils.h"
#include "../../boards/board_detector.h"
#include "../../boards/board_ata_service.h"
#include "../../host/host_widget.h"
#include "../../host/host_widget_registry.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../storage/ata_drive.h"
#include "../../storage/disk_image.h"
#include "imx31_avic.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace {

/* MCIMX31RM §23 (Table 23-8) ATA controller register block, PA 0x43F8C000. */
constexpr uint32_t kBase = 0x43F8C000u;
constexpr uint32_t kSize = 0x00004000u;

constexpr uint32_t kTimingEnd    = 0x17u;  /* TIME_OFF..TIME_CYC, byte regs */
constexpr uint32_t kFifoData32   = 0x18u;
constexpr uint32_t kFifoData16   = 0x1Cu;
constexpr uint32_t kFifoFill     = 0x20u;  /* R-only, halfwords in FIFO */
constexpr uint32_t kAtaControl   = 0x24u;
constexpr uint32_t kIntPending   = 0x28u;  /* R-only */
constexpr uint32_t kIntEnable    = 0x2Cu;
constexpr uint32_t kIntClear     = 0x30u;  /* W1C */
constexpr uint32_t kFifoAlarm    = 0x34u;

/* Drive registers connected to the ATA bus (Table 23-15): DATA is 16-bit at
   0xA0; the 8-bit command-block registers run 0xA4..0xBC at stride 4; the
   control block (alt status / device control) is at 0xD8 — there is a gap
   (0xC0..0xD4 unused), so it is NOT 0xA0+stride*8. */
constexpr uint32_t kDriveData    = 0xA0u;
constexpr uint32_t kDriveTaskLo  = 0xA4u;
constexpr uint32_t kDriveTaskHi  = 0xBCu;
constexpr uint32_t kDriveControl = 0xD8u;

/* INTERRUPT_PENDING/ENABLE bits (§23.3.3.5): the CPU interrupt ipbus_int is
   bits 3-6 only; the drive INTRQ reaches the CPU on ata_intrq2 (bit 3), while
   ata_intrq1 (bit 7) routes the same INTRQ to the SDMA — drive IRQ on bit 7
   alone leaves AVIC source 15 silent for PIO. */
constexpr uint8_t kPendAtaIntrq1 = 0x80u;  /* bit 7 -> SDMA alarm */
constexpr uint8_t kPendCtrlIdle  = 0x10u;  /* bit 4: ATA protocol engine idle */
constexpr uint8_t kPendAtaIntrq2 = 0x08u;  /* bit 3 -> CPU */
constexpr uint8_t kIpbusMask     = 0x78u;  /* bits 3-6 aggregate to ipbus_int */

/* MCIMX31RM §2.2 Table 2-3: AVIC source 15 = ATA controller. */
constexpr uint32_t kAvicSourceAta = 15u;

class Imx31Ata : public Peripheral, public HostWidget {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::iMX31;
    }
    void OnReady() override {
        auto& bas = emu_.Get<BoardAtaService>();
        bas.EnsureExists();
        const std::string path = bas.GetImagePath();
        if (!disk_.Open(path, bas.GetCapacityBytes())) {
            LOG(Caution, "[ATA] FATAL: cannot open core disk '%s' — held by "
                         "another cerf instance, or no write access.\n", path.c_str());
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<HostWidgetRegistry>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    /* HostWidget. RX = sector data read from the drive (kDriveData read),
       TX = sector data written to the drive (kDriveData write). */
    std::wstring WidgetName() const override { return L"Hard Disk"; }
    WidgetGroup  Group() const override { return WidgetGroup::Storage; }
    std::wstring Tooltip() const override { return L"IDE/ATA Hard Disk"; }
    std::vector<WidgetMenuItem> BuildMenu() override {
        WidgetMenuItem hdr;
        hdr.label   = L"IDE/ATA Hard Disk";
        hdr.enabled = false;
        return { std::move(hdr) };
    }
    void DrawIcon(HDC dc, const RECT& box) const override;

    uint8_t ReadByte(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        if (off <= kTimingEnd) return timing_[off];
        switch (off) {
            case kFifoFill:   return 0;
            case kAtaControl: return ata_control_;
            case kIntPending: return PendingBits();
            case kIntEnable:  return int_enable_;
            case kFifoAlarm:  return fifo_alarm_;
        }
        if (auto idx = TaskFileIndex(off)) {
            const uint8_t v = drive_.ReadTaskFile(*idx);
            UpdateAvic();
            return v;
        }
        HaltUnsupportedAccess("ReadByte", addr, 0);
    }

    void WriteByte(uint32_t addr, uint8_t value) override {
        const uint32_t off = addr - kBase;
        if (off <= kTimingEnd) { timing_[off] = value; return; }
        switch (off) {
            case kAtaControl: ata_control_ = value; return;
            case kIntEnable:  int_enable_  = value; UpdateAvic(); return;
            case kIntClear:   return;  /* ata_intrq/idle are level, computed live */
            case kFifoAlarm:  fifo_alarm_  = value; return;
        }
        if (auto idx = TaskFileIndex(off)) {
            drive_.WriteTaskFile(*idx, value);
            UpdateAvic();
            return;
        }
        HaltUnsupportedAccess("WriteByte", addr, value);
    }

    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        if (off == kDriveData) {
            const uint16_t v = drive_.ReadData();
            MarkRx();
            UpdateAvic();
            return v;
        }
        HaltUnsupportedAccess("ReadHalf", addr, 0);
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        const uint32_t off = addr - kBase;
        if (off == kDriveData) {
            drive_.WriteData(value);
            MarkTx();
            UpdateAvic();
            return;
        }
        HaltUnsupportedAccess("WriteHalf", addr, value);
    }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        if (off + 3u <= kTimingEnd) {
            return static_cast<uint32_t>(timing_[off]) |
                   (static_cast<uint32_t>(timing_[off + 1]) << 8) |
                   (static_cast<uint32_t>(timing_[off + 2]) << 16) |
                   (static_cast<uint32_t>(timing_[off + 3]) << 24);
        }
        switch (off) {
            case kFifoData32: case kFifoData16: case kFifoFill: return 0;
            case kAtaControl: return ata_control_;
            case kIntPending: return PendingBits();
            case kIntEnable:  return int_enable_;
            case kFifoAlarm:  return fifo_alarm_;
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - kBase;
        if (off + 3u <= kTimingEnd) {
            timing_[off]     = static_cast<uint8_t>(value);
            timing_[off + 1] = static_cast<uint8_t>(value >> 8);
            timing_[off + 2] = static_cast<uint8_t>(value >> 16);
            timing_[off + 3] = static_cast<uint8_t>(value >> 24);
            return;
        }
        switch (off) {
            case kFifoData32: case kFifoData16: return;
            case kAtaControl: ata_control_ = static_cast<uint8_t>(value); return;
            case kIntEnable:  int_enable_  = static_cast<uint8_t>(value);
                              UpdateAvic(); return;
            case kIntClear:   return;
            case kFifoAlarm:  fifo_alarm_  = static_cast<uint8_t>(value); return;
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

private:
    /* Maps an MMIO byte offset onto the AtaDrive task-file index, or nullopt. */
    static std::optional<uint8_t> TaskFileIndex(uint32_t off) {
        if (off == kDriveControl) return uint8_t{8};
        if (off >= kDriveTaskLo && off <= kDriveTaskHi && (off & 3u) == 0u)
            return static_cast<uint8_t>((off - kDriveData) / 4u);
        return std::nullopt;
    }

    uint8_t PendingBits() const {
        uint8_t p = drive_.DataTransferActive() ? 0u : kPendCtrlIdle;
        if (drive_.IrqAsserted()) p |= kPendAtaIntrq1 | kPendAtaIntrq2;
        return p;
    }

    void UpdateAvic() {
        const bool level = (PendingBits() & int_enable_ & kIpbusMask) != 0u;
        auto& avic = emu_.Get<Imx31Avic>();
        if (level) avic.AssertSource(kAvicSourceAta);
        else       avic.DeassertSource(kAvicSourceAta);
    }

    DiskImage disk_;
    AtaDrive  drive_{&disk_};

    std::array<uint8_t, kTimingEnd + 1> timing_ = [] {
        std::array<uint8_t, kTimingEnd + 1> t{};
        t.fill(0x01u);  /* every timing register resets to 0x01 (Table 23-8) */
        return t;
    }();
    uint8_t ata_control_ = 0, int_enable_ = 0, fifo_alarm_ = 0;
};

void Imx31Ata::DrawIcon(HDC dc, const RECT& box) const {
    const int cx = (box.left + box.right) / 2;
    const int cy = (box.top + box.bottom) / 2;
    RECT body = { cx - 8, cy - 6, cx + 8, cy + 6 };

    HBRUSH  fill = CreateSolidBrush(RGB(48, 52, 60));
    HPEN    pen  = CreatePen(PS_SOLID, 1, RGB(150, 150, 160));
    HGDIOBJ ob   = SelectObject(dc, fill);
    HGDIOBJ op   = SelectObject(dc, pen);
    RoundRect(dc, body.left, body.top, body.right, body.bottom, 3, 3);
    /* Spindle dot — the platter centre. */
    HBRUSH spindle = CreateSolidBrush(RGB(170, 175, 185));
    HGDIOBJ os = SelectObject(dc, spindle);
    Ellipse(dc, cx - 2, cy - 2, cx + 3, cy + 3);
    SelectObject(dc, os);
    DeleteObject(spindle);
    SelectObject(dc, ob);
    SelectObject(dc, op);
    DeleteObject(fill);
    DeleteObject(pen);
}

}  /* namespace */

REGISTER_SERVICE(Imx31Ata);
