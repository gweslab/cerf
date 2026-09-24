#include "../pci/pci_device.h"
#include "../pci/pci_host_bridge.h"
#include "ati_ragexl_display.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../boards/nec_rockhopper/nec_rockhopper_id.h"
#include "../../host/host_window.h"
#include "../../state/state_stream.h"

#include <cstdint>
#include <vector>


namespace {

constexpr uint32_t kVendorId = 0x1002u;   /* ATI */
constexpr uint32_t kDeviceId = 0x4752u;   /* Rage XL (Mach64 "GR") */
constexpr uint8_t  kPciDev   = 1u;        /* bus-0 slot (OS matches by VID/DID, slot-agnostic) */

constexpr uint32_t kFbSize   = 0x00800000u;
constexpr uint32_t kMmioSize = 0x00001000u;
constexpr uint32_t kBarMemPrefetch = 0x8u;    /* PCI BAR bit3: memory prefetchable */
constexpr uint32_t kCmdMemEnable   = 0x2u;    /* PCI command: memory space enable */

/* The four non-latch Mach64 registers. */
constexpr uint32_t kRegConfigChipId  = 0x4E0u;
constexpr uint32_t kRegClockCntl     = 0x490u;
constexpr uint32_t kClockCntlPllWrEn = 0x00000200u;
constexpr uint32_t kPllExtVpllMsb    = 28u;
constexpr uint32_t kPllExtV2pllMsb   = 39u;
constexpr uint8_t  kExtVpllMsbUpdate = 0x08u;
constexpr uint32_t kRegCrtcVline     = 0x410u;       /* CRTC_VLINE_CRNT_VLINE: bits16:27 = live scanline (RXL_CURRENT_VLINE >>16) */
constexpr uint32_t kRegGuiStat       = 0x738u;
constexpr uint32_t kGuiStatIdleReady = 0x03FF0000u;  /* emulated engine: never busy, FIFO always free */

constexpr uint32_t kRegDacCntl       = 0x4C4u;
constexpr uint32_t kDacCmpDis        = 0x00000008u;
constexpr uint32_t kDacCmpOutput     = 0x00000080u;
constexpr uint32_t kRegDstOffPitch    = 0x500u;
constexpr uint32_t kRegDstYX          = 0x50Cu;
constexpr uint32_t kRegDstHeightWidth = 0x518u;
constexpr uint32_t kRegDstCntl        = 0x530u;
constexpr uint32_t kRegSrcOffPitch    = 0x580u;
constexpr uint32_t kRegSrcYX          = 0x58Cu;
constexpr uint32_t kRegClrCmpCntl     = 0x708u;
constexpr uint32_t kRegDpWriteMask    = 0x6C8u;
constexpr uint32_t kRegDpFrgdClr      = 0x6C4u;
constexpr uint32_t kRegDpPixWidth     = 0x6D0u;
constexpr uint32_t kRegDpMix          = 0x6D4u;
constexpr uint32_t kRegDpSrc          = 0x6D8u;
constexpr uint32_t kRegDstWidthHeight = 0x6ECu;
/* CRTC scanout geometry (decoded for the FrameRenderer + display-enable signal). */
constexpr uint32_t kRegCrtcHTotalDisp = 0x400u;
constexpr uint32_t kRegCrtcVTotalDisp = 0x408u;
constexpr uint32_t kRegCrtcOffPitch   = 0x414u;      /* OFFSET bits 0:19 (*8B), PITCH bits 22:31 (*8px) */
constexpr uint32_t kRegCrtcGenCntl    = 0x41Cu;      /* PIX_WIDTH bits 8:10, CrtcEnable, DisplayDis */
constexpr uint32_t kCrtcEnable        = 0x02000000u;
constexpr uint32_t kRegCurClr0         = 0x460u;
constexpr uint32_t kRegCurClr1         = 0x464u;
constexpr uint32_t kRegCurOffset       = 0x468u;
constexpr uint32_t kRegCurHorzVertPosn = 0x46Cu;
constexpr uint32_t kRegCurHorzVertOff  = 0x470u;
constexpr uint32_t kRegGenTestCntl     = 0x4D0u;
constexpr uint32_t kHwCursorEnable     = 0x80u;
struct Bar {
    uint32_t size_mask = 0;   /* e.g. 0xFF800000 for 8 MB; 0 = BAR not implemented */
    uint32_t flags     = 0;   /* low type/prefetch bits OR'd into reads */
    uint32_t base      = 0;   /* written value masked to size; bus driver assigns it */
    uint32_t Read() const { return size_mask ? (base | flags) : 0u; }
    void Write(uint32_t v) { if (size_mask) base = v & size_mask; }
    template <typename F>
    static constexpr void Visit(Bar& b, F& field) {
        field("bar_size_mask", b.size_mask);
        field("bar_flags", b.flags);
        field("bar_base", b.base);
    }
};

class AtiRageXl : public PciDevice, public RageXlDisplay {
public:
    explicit AtiRageXl(CerfEmulator& emu) : RageXlDisplay(emu) {}

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::NecRockhopper;
    }
    void OnReady() override {
        fb_.assign(kFbSize, 0);
        bars_[0] = { ~(kFbSize - 1u),   kBarMemPrefetch, 0 };   /* BAR0: framebuffer */
        bars_[2] = { ~(kMmioSize - 1u), 0u,              0 };   /* BAR2: MMIO regs */
        emu_.Get<PciHostBridge>().RegisterPciDevice(this);
    }

    uint8_t PciDev() const override { return kPciDev; }
    uint8_t PciFnc() const override { return 0u; }

    uint32_t ConfigRead(uint32_t reg) override {
        switch (reg) {
            case 0x00: return kVendorId | (kDeviceId << 16);
            case 0x04: return command_;                    /* status (high 16) = 0 */
            case 0x08: return 0x03000000u;                 /* class 0x03 / sub 0x00 / progif 0x00 / rev 0 */
            case 0x0C: return 0x00000000u;                 /* header type 0, single function */
            case 0x10: case 0x14: case 0x18:               /* BAR0..2 */
                return bars_[(reg - 0x10u) / 4u].Read();
            default:   return 0u;                          /* BAR3..5, expansion ROM, etc. unimplemented */
        }
    }
    void ConfigWrite(uint32_t reg, uint32_t value) override {
        if (reg == 0x04) { command_ = value & 0xFFFFu; return; }
        if (reg >= 0x10u && reg <= 0x18u) bars_[(reg - 0x10u) / 4u].Write(value);
    }

    bool MemClaims(uint32_t addr) const override { return FbHit(addr) || MmioHit(addr); }
    uint32_t MemRead(uint32_t addr, unsigned size) override {
        if (FbHit(addr)) return FbRead(addr - bars_[0].base, size);
        if (MmioHit(addr)) return MmioRead(addr - bars_[2].base, size);
        LogMmio("read", addr, 0);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    void MemWrite(uint32_t addr, uint32_t value, unsigned size) override {
        if (FbHit(addr)) { FbWrite(addr - bars_[0].base, value, size); return; }
        if (MmioHit(addr)) { MmioWrite(addr - bars_[2].base, value, size); return; }
        LogMmio("write", addr, value);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    void SaveState(StateWriter& w) override {
        w.Write("command", command_);
        static_assert(StateVisitCoversAllBytes<Bar>(
                          [](Bar& b, StateFieldBytes& f) { Bar::Visit(b, f); }),
                      "Bar::Visit must name or skip every field of Bar");
        StateWriteField bar_field(w);
        for (Bar& b : bars_) Bar::Visit(b, bar_field);
        w.WriteBytes("fb", fb_.data(), fb_.size());
        w.WriteBytes("regs", regs_, sizeof(regs_));
        w.Write("clock_cntl", clock_cntl_);
        w.WriteBytes("pll", pll_, sizeof(pll_));
        w.Write("crtc_vline", crtc_vline_);
        w.Write("signaled_w", signaled_w_);
        w.Write("signaled_h", signaled_h_);
    }
    void RestoreState(StateReader& r) override {
        r.Read("command", command_);
        StateReadField bar_field(r);
        for (Bar& b : bars_) Bar::Visit(b, bar_field);
        r.ReadBytes("fb", fb_.data(), fb_.size());
        r.ReadBytes("regs", regs_, sizeof(regs_));
        r.Read("clock_cntl", clock_cntl_);
        r.ReadBytes("pll", pll_, sizeof(pll_));
        r.Read("crtc_vline", crtc_vline_);
        r.Read("signaled_w", signaled_w_);
        r.Read("signaled_h", signaled_h_);
    }

    Frame CurrentFrame() const override {
        Frame f;
        const uint32_t gen = RegOut(kRegCrtcGenCntl, 4);
        f.on = (gen & kCrtcEnable) != 0u;
        if (!f.on) return f;
        f.bpp = PixWidthToBpp((gen >> 8) & 0x7u);
        if (f.bpp == 0) { f.on = false; return f; }
        const uint32_t htd  = RegOut(kRegCrtcHTotalDisp, 4);
        const uint32_t vtd  = RegOut(kRegCrtcVTotalDisp, 4);
        const uint32_t offp = RegOut(kRegCrtcOffPitch, 4);
        const uint32_t bytespp = (f.bpp + 7u) / 8u;
        f.width   = (((htd >> 16) & 0x1FFu) + 1u) * 8u;
        f.height  = ((vtd >> 16) & 0x7FFu) + 1u;
        f.stride  = ((offp >> 22) & 0x3FFu) * 8u * bytespp;
        f.start   = (offp & 0xFFFFFu) * 8u;
        f.fb      = fb_.data();
        f.fb_size = fb_.size();
        return f;
    }

    Cursor CurrentCursor() const override {
        Cursor c;
        c.enabled = (RegOut(kRegGenTestCntl, 4) & kHwCursorEnable) != 0u;
        if (!c.enabled) return c;
        const uint32_t posn = RegOut(kRegCurHorzVertPosn, 4);
        const uint32_t off  = RegOut(kRegCurHorzVertOff, 4);
        c.x = static_cast<int>(posn & 0xFFFFu);
        c.y = static_cast<int>((posn >> 16) & 0xFFFFu);
        c.visible_w = 64u - (off & 0x3Fu);          /* CUR_HORZ_OFF crops the trailing columns */
        c.visible_h = 64u - ((off >> 16) & 0x3Fu);  /* CUR_VERT_OFF crops the trailing rows */
        c.clr0 = (RegOut(kRegCurClr0, 4) >> 8) & 0xFFFFFFu;   /* 0xRRGGBBxx -> 0xRRGGBB */
        c.clr1 = (RegOut(kRegCurClr1, 4) >> 8) & 0xFFFFFFu;
        const size_t base = static_cast<size_t>(RegOut(kRegCurOffset, 4)) * 8u;  /* 8-byte units */
        if (base + 64u * 16u > fb_.size()) {        /* sprite must live inside the framebuffer */
            c.enabled = false;
            return c;
        }
        c.def = fb_.data() + base;
        return c;
    }

private:
    static uint32_t PixWidthToBpp(uint32_t code) {
        switch (code) {
            case 1: return 4;  case 2: return 8;  case 3: return 15;
            case 4: return 16; case 5: return 24; case 6: return 32;
            default: return 0;
        }
    }
    void MaybeSignalDisplay() {
        const Frame f = CurrentFrame();
        /* Re-signal on geometry change: the CRTC is enabled before the H/V timing
           is programmed, so the first on-edge carries a degenerate size; resize
           again when the real mode lands. */
        if (f.on && f.width && f.height) {
            if (f.width != signaled_w_ || f.height != signaled_h_) {
                signaled_w_ = f.width;
                signaled_h_ = f.height;
                emu_.Get<HostWindow>().OnLcdEnabled();
            }
        } else {
            signaled_w_ = signaled_h_ = 0;
        }
    }

    static uint32_t Slice(uint32_t dword, uint32_t off, unsigned size) {
        return (dword >> ((off & 3u) * 8u)) & cerf::ByteWidthMask(size);
    }

    uint32_t RegOut(uint32_t off, unsigned size) const {
        uint32_t v = 0;
        for (unsigned i = 0; i < size; ++i) v |= uint32_t(regs_[(off + i) & 0xFFFu]) << (i * 8);
        return v;
    }
    void RegIn(uint32_t off, uint32_t value, unsigned size) {
        for (unsigned i = 0; i < size; ++i) regs_[(off + i) & 0xFFFu] = uint8_t(value >> (i * 8));
    }

    uint32_t MmioRead(uint32_t off, unsigned size) {
        const uint32_t a = off & ~3u;
        if (a == kRegConfigChipId) return Slice(kDeviceId, off, size);
        if (a == kRegGuiStat)      return Slice(kGuiStatIdleReady, off, size);
        if (a == kRegCrtcVline)    return Slice((RegOut(a, 4) & 0xFFFFu) | ((crtc_vline_++ & 0xFFFu) << 16), off, size);
        if (a == kRegDacCntl) {
            uint32_t v = RegOut(a, 4);
            if (!(v & kDacCmpDis)) v |= kDacCmpOutput;  /* compare enabled: connected CRT trips the comparator */
            return Slice(v, off, size);
        }
        if (a == kRegClockCntl) {
            const uint32_t idx = (clock_cntl_ >> 10) & 0x3Fu;
            const uint32_t cc  = (clock_cntl_ & ~0x00FF0000u) | (uint32_t(pll_[idx]) << 16);
            return Slice(cc, off, size);
        }
        return RegOut(off, size);                                  /* control/timing latch store-readback */
    }
    void MmioWrite(uint32_t off, uint32_t value, unsigned size) {
        const uint32_t a = off & ~3u;
        if (a == kRegClockCntl) {
            const unsigned bytepos = off - kRegClockCntl;
            for (unsigned i = 0; i < size && bytepos + i < 4u; ++i) {
                const unsigned sh = (bytepos + i) * 8u;
                clock_cntl_ = (clock_cntl_ & ~(0xFFu << sh)) | (((value >> (i * 8u)) & 0xFFu) << sh);
            }
            const uint32_t idx = (clock_cntl_ >> 10) & 0x3Fu;
            if (bytepos <= 2u && bytepos + size > 2u && (clock_cntl_ & kClockCntlPllWrEn)) {
                uint8_t data = (clock_cntl_ >> 16) & 0xFFu;
                if (idx == kPllExtVpllMsb || idx == kPllExtV2pllMsb) data &= ~kExtVpllMsbUpdate;
                pll_[idx] = data;
            }
            return;
        }
        RegIn(off, value, size);                                  /* control/timing latch store-readback */
        if (a == kRegDstHeightWidth || a == kRegDstWidthHeight) ExecuteEngineOp(off, value);
        if (a == kRegCrtcGenCntl) MaybeSignalDisplay();
    }

    static uint32_t Rop(uint32_t code, uint32_t d, uint32_t s) {
        switch (code & 0xFu) {
            case 0:  return ~d;        case 1:  return 0u;          case 2:  return 0xFFFFFFFFu;
            case 3:  return d;         case 4:  return ~s;          case 5:  return d ^ s;
            case 6:  return ~(d ^ s);  case 7:  return s;           case 8:  return ~d | ~s;
            case 9:  return d | ~s;    case 10: return ~d | s;      case 11: return d | s;
            case 12: return d & s;     case 13: return ~d & s;      case 14: return d & ~s;
            default: return ~d & ~s;   /* 15 */
        }
    }
    [[noreturn]] void EngineOob(const char* what, uint32_t addr) const {
        LOG(Caution, "AtiRageXl: 2D engine %s out of framebuffer (addr=0x%X fb_size=0x%zX)\n",
            what, addr, fb_.size());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    uint32_t FbPixel(uint32_t addr, uint32_t bytespp) const {
        if (addr + bytespp > fb_.size()) EngineOob("read", addr);
        return static_cast<uint32_t>(cerf::le::UN(fb_.data() + addr, bytespp));
    }

    void ExecuteEngineOp(uint32_t launch_off, uint32_t launch_val) {
        const uint32_t off_pitch = RegOut(kRegDstOffPitch, 4);
        const uint32_t bytespp = (PixWidthToBpp(RegOut(kRegDpPixWidth, 4) & 0x7u) + 7u) / 8u;
        const uint32_t base    = (off_pitch & 0x003FFFFFu) * 8u;
        const uint32_t pitch   = ((off_pitch >> 22) & 0x3FFu) * 8u * bytespp;
        const uint32_t yx      = RegOut(kRegDstYX, 4);
        const uint32_t dst_x   = (yx >> 16) & 0xFFFFu;
        const uint32_t dst_y   = yx & 0xFFFFu;
        const uint32_t w       = (launch_val >> 16) & 0x3FFFu;
        const uint32_t h       = launch_val & 0x3FFFu;
        const uint32_t frgd_src = RegOut(kRegDpSrc, 4) & 0x700u;
        const uint32_t mix_code = (RegOut(kRegDpMix, 4) >> 16) & 0x1Fu;
        const uint32_t wmask    = RegOut(kRegDpWriteMask, 4);
        const bool full_mask = (wmask == 0u || wmask == 0xFFFFFFFFu);
        const bool transp = (RegOut(kRegClrCmpCntl, 4) & 0x01000000u) != 0;
        if (bytespp && full_mask && !transp && mix_code <= 15u &&
            (frgd_src == 0x100u || frgd_src == 0x300u)) {
            const bool   is_blit = (frgd_src == 0x300u);
            const uint32_t fg    = RegOut(kRegDpFrgdClr, 4);
            const uint32_t sop   = RegOut(kRegSrcOffPitch, 4);
            const uint32_t sbase = (sop & 0x003FFFFFu) * 8u;
            const uint32_t spitch = ((sop >> 22) & 0x3FFu) * 8u * bytespp;
            const uint32_t syx   = RegOut(kRegSrcYX, 4);
            const int src_x = (int)((syx >> 16) & 0xFFFFu);
            const int src_y = (int)(syx & 0xFFFFu);
            const uint32_t cntl = RegOut(kRegDstCntl, 4);
            const int xs = (cntl & 0x1u) ? 1 : -1;   /* DST_X_LEFT_TO_RIGHT */
            const int ys = (cntl & 0x2u) ? 1 : -1;   /* DST_Y_TOP_TO_BOTTOM */
            for (uint32_t r = 0; r < h; ++r) {
                const int dyr = (int)dst_y + (int)r * ys;
                const int syr = src_y + (int)r * ys;
                if (dyr < 0 || (is_blit && syr < 0)) EngineOob("row coord", 0);
                for (uint32_t c = 0; c < w; ++c) {
                    const int dxc = (int)dst_x + (int)c * xs;
                    const int sxc = src_x + (int)c * xs;
                    if (dxc < 0 || (is_blit && sxc < 0)) EngineOob("col coord", 0);
                    const uint32_t da = base + (uint32_t)dyr * pitch + (uint32_t)dxc * bytespp;
                    if (da + bytespp > fb_.size()) EngineOob("write", da);
                    const uint32_t s = is_blit ? FbPixel(sbase + (uint32_t)syr * spitch + (uint32_t)sxc * bytespp, bytespp) : fg;
                    const uint32_t res = (mix_code == 7u) ? s : Rop(mix_code, FbPixel(da, bytespp), s);
                    cerf::le::PutN(fb_.data() + da, res, bytespp);
                }
            }
            return;
        }

        LOG(Caution, "AtiRageXl: Mach64 2D engine op NOT IMPLEMENTED - launch reg+0x%03X dims=0x%08X "
            "DP_SRC=0x%08X DP_MIX=0x%08X DP_PIX_WIDTH=0x%08X DST_OFF_PITCH=0x%08X DST_Y_X=0x%08X "
            "DST_CNTL=0x%08X DP_FRGD_CLR=0x%08X SRC_OFF_PITCH=0x%08X DP_WRITE_MASK=0x%08X CLR_CMP_CNTL=0x%08X\n",
            launch_off, launch_val,
            RegOut(kRegDpSrc, 4), RegOut(kRegDpMix, 4), RegOut(kRegDpPixWidth, 4),
            RegOut(kRegDstOffPitch, 4), RegOut(kRegDstYX, 4), RegOut(kRegDstCntl, 4),
            RegOut(kRegDpFrgdClr, 4), RegOut(kRegSrcOffPitch, 4), wmask, RegOut(kRegClrCmpCntl, 4));
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    bool MemEnabled() const { return (command_ & kCmdMemEnable) != 0; }
    bool FbHit(uint32_t a) const {
        return MemEnabled() && bars_[0].base && a >= bars_[0].base && a < bars_[0].base + kFbSize;
    }
    bool MmioHit(uint32_t a) const {
        return MemEnabled() && bars_[2].base && a >= bars_[2].base && a < bars_[2].base + kMmioSize;
    }
    uint32_t FbRead(uint32_t off, unsigned size) const {
        uint32_t v = 0;
        for (unsigned i = 0; i < size && off + i < fb_.size(); ++i) v |= uint32_t(fb_[off + i]) << (i * 8);
        return v;
    }
    void FbWrite(uint32_t off, uint32_t value, unsigned size) {
        for (unsigned i = 0; i < size && off + i < fb_.size(); ++i) fb_[off + i] = uint8_t(value >> (i * 8));
    }
    void LogMmio(const char* op, uint32_t addr, uint32_t value) {
        LOG(Caution, "AtiRageXl: Mach64 MMIO %s reg+0x%03X val=0x%08X out of BAR\n",
            op, addr - bars_[2].base, value);
    }

    uint32_t command_ = 0;
    Bar bars_[3];
    std::vector<uint8_t> fb_;
    uint8_t  regs_[4096] = {};
    uint32_t clock_cntl_ = 0;
    uint8_t  pll_[64]    = {};
    uint32_t crtc_vline_ = 0;
    uint32_t signaled_w_ = 0;
    uint32_t signaled_h_ = 0;
};

REGISTER_SERVICE_AS(AtiRageXl, RageXlDisplay);

}  /* namespace */
