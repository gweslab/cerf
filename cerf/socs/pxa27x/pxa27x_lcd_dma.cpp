#include "pxa27x_lcd_dma.h"

#include "../../boards/board_context.h"
#include "pxa270_id.h"
#include "pxa27x_lcd.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../cpu/emulated_memory.h"
#include "../../state/state_stream.h"

namespace {
constexpr uint32_t kDmaBase = 0x200u;
constexpr uint32_t kDmaEnd  = 0x270u;

/* Intel PXA27x Developer's Manual 280000-001 Table 7-55: FBR0..FBR4 at
   0x020..0x030, FBR5 at 0x110, FBR6 at 0x114. */
constexpr uint32_t kFbr0 = 0x020u;
constexpr uint32_t kFbr4 = 0x030u;
constexpr uint32_t kFbr5 = 0x110u;
constexpr uint32_t kFbr6 = 0x114u;

constexpr uint32_t kFbrBra  = 1u << 0;
constexpr uint32_t kFbrBint = 1u << 1;

/* Intel PXA27x Developer's Manual 280000-001 Table 7-63. */
constexpr uint32_t kLdcmdPal     = 1u << 26;
constexpr uint32_t kLdcmdSofint  = 1u << 22;
constexpr uint32_t kLdcmdEofint  = 1u << 21;
constexpr uint32_t kLdcmdLenMask = 0x001FFFFCu;

constexpr uint32_t kDescAddrMask = 0xFFFFFFF0u;
constexpr uint32_t kSrcAddrMask  = 0xFFFFFFF0u;
constexpr uint32_t kFrameIdMask  = 0xFFFFFFF8u;
}

bool Pxa27xLcdDma::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Pxa270;
}

bool Pxa27xLcdDma::Decodes(uint32_t off) {
    if (off >= kDmaBase && off < kDmaEnd) return (off & 0x3u) == 0;
    return (off >= kFbr0 && off <= kFbr4 && (off & 0x3u) == 0) || off == kFbr5 || off == kFbr6;
}

uint32_t* Pxa27xLcdDma::SlotLocked(uint32_t off) {
    if (off >= kDmaBase && off < kDmaEnd) {
        const uint32_t ch = (off - kDmaBase) / 0x10u;
        switch ((off - kDmaBase) & 0xCu) {
        case 0x0u: return &fdadr_[ch];
        case 0x4u: return &fsadr_[ch];
        case 0x8u: return &fidr_ [ch];
        default:   return &ldcmd_[ch];
        }
    }
    if (off == kFbr5) return &fbr_[5];
    if (off == kFbr6) return &fbr_[6];
    return &fbr_[(off - kFbr0) / 4u];
}

uint32_t Pxa27xLcdDma::Read(uint32_t off) {
    std::lock_guard<std::mutex> lk(mtx_);
    return *SlotLocked(off);
}

void Pxa27xLcdDma::Write(uint32_t off, uint32_t value) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (off < kDmaBase) {
        *SlotLocked(off) = value;
        return;
    }
    if (((off - kDmaBase) & 0xCu) != 0x0u) return;
    if (off == kDmaBase && dma_halted_) {
        emu_.Get<Fatal>().Die("Pxa27xLcdDma: FDADR0 write 0x%08X after a bus error; the DMA "
                              "restart is not modelled", value);
    }
    *SlotLocked(off) = value & kDescAddrMask;
}

Pxa27xLcdDma::Fetch Pxa27xLcdDma::FetchChannel0() {
    std::lock_guard<std::mutex> lk(mtx_);
    Fetch f;
    /* Intel PXA27x Developer's Manual 280000-001 Table 7-55 bit 0 BRA: the next
       Descriptor is fetched from the Frame Branch Address; BRA clears after
       loading it. */
    uint32_t desc = fdadr_[0] & kDescAddrMask;
    if (fbr_[0] & kFbrBra) {
        desc       = fbr_[0] & kSrcAddrMask;
        f.branched = (fbr_[0] & kFbrBint) != 0;
        fbr_[0]   &= ~kFbrBra;
    }

    /* Intel PXA27x Developer's Manual 280000-001 Table 7-58 bit 2 BER: the DMA
       controller stops and is halted until FDADR of the BER_CH channel is
       programmed. */
    auto& mem = emu_.Get<EmulatedMemory>();
    if (!mem.TryTranslate(desc)) {
        dma_halted_ = true;
        f.branched  = false;
        f.frame_id  = fidr_[0];
        return f;
    }

    fdadr_[0] = mem.ReadWord(desc + 0x0u) & kDescAddrMask;
    fsadr_[0] = mem.ReadWord(desc + 0x4u) & kSrcAddrMask;
    fidr_ [0] = mem.ReadWord(desc + 0x8u) & kFrameIdMask;
    ldcmd_[0] = mem.ReadWord(desc + 0xCu);

    f.loaded   = true;
    f.sof      = (ldcmd_[0] & kLdcmdSofint) != 0;
    f.frame_id = fidr_[0];
    return f;
}

bool Pxa27xLcdDma::Channel0EndOfFrame() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return (ldcmd_[0] & kLdcmdEofint) != 0;
}

uint32_t Pxa27xLcdDma::Channel0FrameId() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return fidr_[0];
}

bool Pxa27xLcdDma::Halted() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return dma_halted_;
}

uint32_t Pxa27xLcdDma::SrcPa(uint32_t channel) const {
    if (channel >= kChannels) return 0;
    std::lock_guard<std::mutex> lk(mtx_);
    return fsadr_[channel] & kSrcAddrMask;
}

uint32_t Pxa27xLcdDma::Length(uint32_t channel) const {
    if (channel >= kChannels) return 0;
    std::lock_guard<std::mutex> lk(mtx_);
    return ldcmd_[channel] & kLdcmdLenMask;
}

bool Pxa27xLcdDma::IsPalette(uint32_t channel) const {
    if (channel >= kChannels) return false;
    std::lock_guard<std::mutex> lk(mtx_);
    return (ldcmd_[channel] & kLdcmdPal) != 0;
}

/* Intel PXA27x Developer's Manual 280000-001 Section 7.5.1.2 (page 7-54): "Multiple
   descriptors can be chained together in a list"; Table 7-63 (page 7-119): LENGTH in
   bytes "for frame data is a function of the screen size and the pixel size". */
void Pxa27xLcdDma::RequireWholeFrame(uint32_t bpp_code, uint64_t w, uint64_t h) const {
    if (bpp_code != Pxa27xLcd::kBppCode16Bpp) {
        emu_.Get<Fatal>().Die("Pxa27xLcdDma: channel 0 frame length at BPP code 0x%X is not "
                              "modelled", bpp_code);
    }
    const uint32_t length = Length(0);
    if (length != w * h * Pxa27xLcd::kBytesPerPixel16Bpp) {
        emu_.Get<Fatal>().Die("Pxa27xLcdDma: channel 0 descriptor LENGTH %u is not the "
                              "%llux%llu 16-bpp frame; a frame split across chained "
                              "descriptors is not modelled", length,
                              static_cast<unsigned long long>(w),
                              static_cast<unsigned long long>(h));
    }
}

void Pxa27xLcdDma::Reset() {
    std::lock_guard<std::mutex> lk(mtx_);
    for (uint32_t ch = 0; ch < kChannels; ++ch) {
        fdadr_[ch] = 0u;
        fsadr_[ch] = 0u;
        fidr_ [ch] = 0u;
        ldcmd_[ch] = 0u;
        fbr_  [ch] = 0u;
    }
    dma_halted_ = false;
}

template <typename F>
void Pxa27xLcdDma::VisitRegs(F& f) {
    for (uint32_t i = 0; i < kChannels; ++i) {
        f("fdadr", fdadr_[i]);
        f("fsadr", fsadr_[i]);
        f("fidr", fidr_ [i]);
        f("ldcmd", ldcmd_[i]);
        f("fbr", fbr_  [i]);
    }
}

void Pxa27xLcdDma::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mtx_);
    StateWriteField f(w);
    VisitRegs(f);
    w.Write<uint8_t>("dma_halted", dma_halted_ ? 1u : 0u);
}

void Pxa27xLcdDma::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    StateReadField f(r);
    VisitRegs(f);
    uint8_t halted = 0;
    r.Read("dma_halted", halted);
    dma_halted_ = halted != 0u;
}

REGISTER_SERVICE(Pxa27xLcdDma);
