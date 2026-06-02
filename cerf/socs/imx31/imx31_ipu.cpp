#include "imx31_ipu.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../host/host_window.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "imx31_avic.h"

namespace {

/* IPU_CONF enables, MCIMX31RM Fig 44-8 / Table 44-17. SDC_EN bit 4, DI_EN bit 6.
   Recovery drives the panel via DI alone (DI_EN set, SDC_EN clear) — gating the
   display-active check on SDC_EN only leaves the recovery splash blank. */
constexpr uint32_t kIpuConfSdcEnBit = 1u << 4;
constexpr uint32_t kIpuConfDiEnBit  = 1u << 6;
constexpr uint32_t kIpuConfDisplayOn = kIpuConfSdcEnBit | kIpuConfDiEnBit;
constexpr uint32_t kSdcVsyncBit     = 1u << 16;

constexpr uint32_t kIpuConfOff   = 0x00u;
constexpr uint32_t kImaAddrOff   = 0x20u;
constexpr uint32_t kImaDataOff   = 0x24u;
constexpr uint32_t kIntCtrl3Off  = 0x30u;
constexpr uint32_t kIntStat3Off  = 0x44u;
constexpr uint32_t kSdcHorOff    = 0xD0u;
constexpr uint32_t kSdcVerOff    = 0xD4u;

constexpr uint32_t kAvicSourceIpuGeneral = 42u;

constexpr uint8_t  kImaMemChannelParam   = 0x1u;
constexpr uint32_t kSdcBgChannel         = 14u;

struct ResetEntry { uint32_t off; uint32_t value; };
constexpr ResetEntry kNonZeroResets[] = {
    { 0x08Cu, 0x20002000u },
    { 0x090u, 0x20002000u },
    { 0x094u, 0x20002000u },
    { 0x0E0u, 0x20200420u },
    { 0x160u, 0x0000FFFFu }, { 0x164u, 0x0000FFFFu }, { 0x168u, 0x0000FFFFu },
    { 0x16Cu, 0x0000FFFFu }, { 0x170u, 0x0000FFFFu }, { 0x174u, 0x0000FFFFu },
    { 0x178u, 0x0000FFFFu }, { 0x17Cu, 0x0000FFFFu }, { 0x180u, 0x0000FFFFu },
    { 0x184u, 0x0000FFFFu }, { 0x188u, 0x0000FFFFu }, { 0x18Cu, 0x0000FFFFu },
    { 0x190u, 0x0000FFFFu }, { 0x194u, 0x0000FFFFu }, { 0x198u, 0x0000FFFFu },
    { 0x19Cu, 0x0000FFFFu }, { 0x1A0u, 0x0000FFFFu }, { 0x1A4u, 0x0000FFFFu },
    { 0x1A8u, 0x0000FFFFu }, { 0x1ACu, 0x0000FFFFu }, { 0x1B0u, 0x0000FFFFu },
};

enum class Kind { RW, ROnly, W1S, W1C };

Kind ClassifyOffset(uint32_t off) {
    if (off == 0x01Cu) return Kind::ROnly;
    if (off == 0x058u) return Kind::ROnly;
    if (off == 0x0B0u) return Kind::ROnly;
    if (off == 0x004u) return Kind::W1S;
    if (off == 0x008u) return Kind::W1S;
    if (off >= 0x03Cu && off <= 0x04Cu) return Kind::W1C;
    return Kind::RW;
}

}  /* namespace */

bool Imx31Ipu::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    return bd && bd->GetSoc() == SocFamily::iMX31;
}

void Imx31Ipu::OnReady() {
    std::lock_guard<std::mutex> guard(state_mtx_);
    ApplyResetsLocked();
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void Imx31Ipu::ApplyResetsLocked() {
    for (uint32_t i = 0; i < kRegCount; ++i) regs_[i] = 0u;
    for (const auto& e : kNonZeroResets) regs_[e.off / 4u] = e.value;
    for (uint32_t i = 0; i < kCpmDwordCount; ++i) cpm_[i] = 0u;
    ima_mem_nu_  = 0;
    ima_row_nu_  = 0;
    ima_word_nu_ = 0;
}

uint32_t Imx31Ipu::ReadRegLocked(uint32_t off) const {
    uint32_t slot;
    if (!OffsetToSlot(off, &slot)) return 0;
    return regs_[slot];
}

void Imx31Ipu::WriteRegLocked(uint32_t off, uint32_t value) {
    uint32_t slot;
    if (!OffsetToSlot(off, &slot)) return;
    switch (ClassifyOffset(off)) {
    case Kind::ROnly: break;
    case Kind::W1S:   regs_[slot] |=  value; break;
    case Kind::W1C:   regs_[slot] &= ~value; break;
    case Kind::RW:    regs_[slot] = value;   break;
    }
}

void Imx31Ipu::OnIpuConfWriteLocked(uint32_t old_conf, uint32_t new_conf) {
    /* Publish dims on the display-on edge (SDC_EN or DI_EN) — the guest enabling
       the panel is the ODO LCD_ON-edge equivalent, on the JIT thread where
       HostWindow exists. */
    const bool was_on = (old_conf & kIpuConfDisplayOn) != 0;
    const bool now_on = (new_conf & kIpuConfDisplayOn) != 0;
    if (was_on == now_on) return;
    PublishSdcDimsLocked();
}

void Imx31Ipu::OnImaAddrWriteLocked(uint32_t value) {
    ima_mem_nu_  = static_cast<uint8_t> ((value >> 16) & 0xFu);
    ima_row_nu_  = static_cast<uint16_t>((value >>  3) & 0x1FFFu);
    ima_word_nu_ = static_cast<uint8_t> ( value        & 0x7u);
}

void Imx31Ipu::OnImaDataWriteLocked(uint32_t value) {
    if (ima_mem_nu_ == kImaMemChannelParam &&
        ima_row_nu_ < kCpmRows &&
        ima_word_nu_ < kCpmDwordsPerRow) {
        cpm_[ima_row_nu_ * kCpmDwordsPerRow + ima_word_nu_] = value;
        /* The bg channel's frame size (FW/FH) is the real display resolution and
           is programmed here, after the panel-enable edge that first sized the
           window — re-publish so the window tracks it (deduped in Publish). */
        if ((ima_row_nu_ >> 1) == kSdcBgChannel) PublishSdcDimsLocked();
    }
    /* §44.3.3.1.9 (PDF p2034): WORD_NU auto-increments per write to
       IMA_DATA; on overflow ROW_NU advances and WORD_NU resets. */
    uint8_t max_word_nu = kCpmDwordsPerRow - 1u;
    if (ima_mem_nu_ != kImaMemChannelParam) max_word_nu = 0;
    if (ima_word_nu_ >= max_word_nu) {
        ima_word_nu_ = 0;
        ++ima_row_nu_;
    } else {
        ++ima_word_nu_;
    }
}

void Imx31Ipu::PublishSdcDimsLocked() {
    if ((regs_[0] & kIpuConfDisplayOn) == 0) return;
    uint32_t w, h;
    EffectiveDimsLocked(&w, &h);
    if (w <= 1u || h <= 1u) return;
    if (w == last_pub_w_ && h == last_pub_h_) return;
    last_pub_w_ = w;
    last_pub_h_ = h;
    emu_.Get<HostWindow>().OnLcdEnabled(w, h);
}

void Imx31Ipu::RouteSdc3VsyncToAvicLocked() {
    const uint32_t ctrl = regs_[kIntCtrl3Off / 4u];
    const uint32_t stat = regs_[kIntStat3Off / 4u];
    const bool gated = (ctrl & kSdcVsyncBit) != 0 && (stat & kSdcVsyncBit) != 0;
    if (gated) emu_.Get<Imx31Avic>().AssertSource(kAvicSourceIpuGeneral);
    else       emu_.Get<Imx31Avic>().DeassertSource(kAvicSourceIpuGeneral);
}

uint32_t Imx31Ipu::ExtractBitsFromWord1(const uint32_t* w1_dwords,
                                        uint32_t lsb,
                                        uint32_t width) {
    const uint32_t dword_idx    = lsb / 32u;
    const uint32_t bit_in_dword = lsb % 32u;
    if (dword_idx >= kCpmDwordsPerRow) return 0;
    uint64_t combined = static_cast<uint64_t>(w1_dwords[dword_idx]);
    if (bit_in_dword + width > 32u && dword_idx + 1u < kCpmDwordsPerRow) {
        combined |= static_cast<uint64_t>(w1_dwords[dword_idx + 1u]) << 32;
    }
    return static_cast<uint32_t>((combined >> bit_in_dword) &
                                 ((1ull << width) - 1ull));
}

Imx31Ipu::ChannelFormat
Imx31Ipu::DecodeChannelFormatLocked(uint32_t channel) const {
    ChannelFormat f;
    if (channel >= 64u) return f;
    const uint32_t w0_row = 2u * channel;
    const uint32_t w1_row = w0_row + 1u;
    const uint32_t* w0 = &cpm_[w0_row * kCpmDwordsPerRow];
    const uint32_t* w1 = &cpm_[w1_row * kCpmDwordsPerRow];

    /* §44.4 Table 44-29..33 Word0: FW W0[119:108], FH W0[131:120]
       (frame width / height minus 1, in pixels / rows). */
    f.fw = static_cast<uint16_t>(ExtractBitsFromWord1(w0, 108, 12) + 1u);
    f.fh = static_cast<uint16_t>(ExtractBitsFromWord1(w0, 120, 12) + 1u);

    const uint32_t bpp_code = ExtractBitsFromWord1(w1, 64, 3);
    switch (bpp_code) {
    case 0: f.bpp_bits = 32; break;
    case 1: f.bpp_bits = 24; break;
    case 2: f.bpp_bits = 16; break;
    case 3: f.bpp_bits =  8; break;
    case 4: f.bpp_bits =  4; break;
    case 5: f.bpp_bits =  1; break;
    default: f.bpp_bits = 0; break;
    }

    f.stride = static_cast<uint16_t>(ExtractBitsFromWord1(w1, 67, 14) + 1u);

    const uint32_t pfs_code = ExtractBitsFromWord1(w1, 81, 3);
    switch (pfs_code) {
    case 4: f.pfs = PfsKind::RgbPack; break;
    case 6: f.pfs = PfsKind::Yuv422;  break;
    case 7: f.pfs = PfsKind::Generic; break;
    default: f.pfs = PfsKind::Unknown; break;
    }

    f.ofs[0] = 0;
    f.ofs[1] = static_cast<uint8_t>(ExtractBitsFromWord1(w1, 104, 5));
    f.ofs[2] = static_cast<uint8_t>(ExtractBitsFromWord1(w1, 109, 5));
    f.ofs[3] = static_cast<uint8_t>(ExtractBitsFromWord1(w1, 114, 5));
    f.wid[0] = static_cast<uint8_t>(ExtractBitsFromWord1(w1, 119, 3) + 1u);
    f.wid[1] = static_cast<uint8_t>(ExtractBitsFromWord1(w1, 122, 3) + 1u);
    f.wid[2] = static_cast<uint8_t>(ExtractBitsFromWord1(w1, 125, 3) + 1u);
    f.wid[3] = static_cast<uint8_t>(ExtractBitsFromWord1(w1, 128, 3) + 1u);
    return f;
}

uint32_t Imx31Ipu::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off > kLastOff || (off & 0x3u) != 0u) HaltUnsupportedAccess("ReadWord", addr, 0);
    std::lock_guard<std::mutex> guard(state_mtx_);
    return ReadRegLocked(off);
}

void Imx31Ipu::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off > kLastOff || (off & 0x3u) != 0u) HaltUnsupportedAccess("WriteWord", addr, value);
    std::lock_guard<std::mutex> guard(state_mtx_);
    const uint32_t old_val = ReadRegLocked(off);
    WriteRegLocked(off, value);
    if (off == kIpuConfOff)  OnIpuConfWriteLocked(old_val, regs_[0]);
    if (off == kImaAddrOff)  OnImaAddrWriteLocked(value);
    if (off == kImaDataOff)  OnImaDataWriteLocked(value);
    if (off == kSdcHorOff || off == kSdcVerOff) PublishSdcDimsLocked();
    if (off == kIntStat3Off || off == kIntCtrl3Off) RouteSdc3VsyncToAvicLocked();
}

bool Imx31Ipu::IsEnabled() const {
    std::lock_guard<std::mutex> guard(state_mtx_);
    return (regs_[0] & kIpuConfDisplayOn) != 0;
}

void Imx31Ipu::EffectiveDimsLocked(uint32_t* w, uint32_t* h) const {
    /* Displayed resolution is the SDC bg channel's frame size (the framebuffer
       the IPU DMA actually scans), not SCREEN_WIDTH/HEIGHT panel timing: some
       drivers program SCREEN wider than the active frame (gemstone sets 266x336
       for a 240x320 frame). Fall back to SCREEN before the channel is set up. */
    const ChannelFormat f = DecodeChannelFormatLocked(kSdcBgChannel);
    if (f.fw > 1u && f.fh > 1u) {
        *w = f.fw;
        *h = f.fh;
        return;
    }
    *w = ((regs_[kSdcHorOff / 4u] >> 16) & 0x3FFu) + 1u;
    *h = ((regs_[kSdcVerOff / 4u] >> 16) & 0x3FFu) + 1u;
}

uint32_t Imx31Ipu::GetGuestW() const {
    std::lock_guard<std::mutex> guard(state_mtx_);
    uint32_t w, h;
    EffectiveDimsLocked(&w, &h);
    return w;
}

uint32_t Imx31Ipu::GetGuestH() const {
    std::lock_guard<std::mutex> guard(state_mtx_);
    uint32_t w, h;
    EffectiveDimsLocked(&w, &h);
    return h;
}

uint32_t Imx31Ipu::GetSdcBgFbPa() const {
    std::lock_guard<std::mutex> guard(state_mtx_);
    const uint32_t row = 2u * kSdcBgChannel + 1u;
    return cpm_[row * kCpmDwordsPerRow + 0u];
}

Imx31Ipu::ChannelFormat Imx31Ipu::GetSdcBgFormat() const {
    std::lock_guard<std::mutex> guard(state_mtx_);
    return DecodeChannelFormatLocked(kSdcBgChannel);
}

void Imx31Ipu::SetupSdcScanout(uint32_t fb_pa, uint32_t w, uint32_t h) {
    std::lock_guard<std::mutex> guard(state_mtx_);

    /* Encode the SDC bg channel CPM descriptor — exact inverse of
       DecodeChannelFormatLocked / GetSdcBgFbPa for RGB565. */
    auto set = [](uint32_t* row, uint32_t lsb, uint32_t width, uint32_t val) {
        for (uint32_t i = 0; i < width; ++i)
            if ((val >> i) & 1u) row[(lsb + i) / 32u] |= 1u << ((lsb + i) % 32u);
    };
    uint32_t* w0 = &cpm_[(2u * kSdcBgChannel)      * kCpmDwordsPerRow];
    uint32_t* w1 = &cpm_[(2u * kSdcBgChannel + 1u) * kCpmDwordsPerRow];
    for (uint32_t i = 0; i < kCpmDwordsPerRow; ++i) { w0[i] = 0u; w1[i] = 0u; }
    set(w0, 108, 12, w - 1u);       /* FW */
    set(w0, 120, 12, h - 1u);       /* FH */
    w1[0] = fb_pa;                   /* EBA */
    set(w1,  64,  3, 2u);           /* bpp_code = 16bpp */
    set(w1,  67, 14, w * 2u - 1u);  /* stride - 1 */
    set(w1,  81,  3, 4u);           /* pfs = RgbPack */
    set(w1, 104,  5, 5u);           /* green offset */
    set(w1, 109,  5, 11u);          /* red offset */
    set(w1, 119,  3, 5u - 1u);      /* blue width 5 */
    set(w1, 122,  3, 6u - 1u);      /* green width 6 */
    set(w1, 125,  3, 5u - 1u);      /* red width 5 */

    regs_[kSdcHorOff / 4u] = (w - 1u) << 16;
    regs_[kSdcVerOff / 4u] = (h - 1u) << 16;
    /* Leave the display disabled — the guest's IPU_CONF enable write is the edge
       that publishes dims (OnIpuConfWriteLocked). Pre-enabling here suppresses
       that edge, and publishing here deadlocks (HostWindow created off-boot-thread). */
}

void Imx31Ipu::OnHostTick() {
    std::lock_guard<std::mutex> guard(state_mtx_);
    if ((regs_[0] & kIpuConfSdcEnBit) == 0) return;
    regs_[kIntStat3Off / 4u] |= kSdcVsyncBit;
    RouteSdc3VsyncToAvicLocked();
}

REGISTER_SERVICE(Imx31Ipu);
