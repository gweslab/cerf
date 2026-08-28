#include "casio_cassiopeia_em500_display.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../state/state_stream.h"

#include <cstring>

namespace {

constexpr uint32_t kOffPanelEnable = 0x0980u;
constexpr uint32_t kOffPanel0984   = 0x0984u;
constexpr uint32_t kOffPanel0988   = 0x0988u;
constexpr uint32_t kOffBrightness  = 0x098Cu;
constexpr uint32_t kOffPanel0994   = 0x0994u;
constexpr uint32_t kOffPanel0998   = 0x0998u;   /* nk_main_kernel.exe sub_9F034498 @0x9F0344EC (sw 0) */
constexpr uint32_t kOffContrast    = 0x099Cu;

constexpr uint32_t kOffBlitGo  = 0x0A00u;
constexpr uint32_t kOffBlitOp  = 0x0A04u;
constexpr uint32_t kOffBlitLen = 0x0A08u;
constexpr uint32_t kOffBlitSrc = 0x0A10u;
constexpr uint32_t kOffBlitDst = 0x0A14u;

/* ddi.dll sub_FC48A0 @0xFC48A0. */
constexpr uint32_t kOffFillCmd    = 0x0200u;
constexpr uint32_t kOffFillColor  = 0x0204u;
constexpr uint32_t kOffFillWidth  = 0x0208u;
constexpr uint32_t kOffFillHeight = 0x020Cu;
constexpr uint32_t kOffFillDstLo  = 0x0210u;
constexpr uint32_t kOffFillDstHi  = 0x0214u;
constexpr uint32_t kOffFillGo      = 0x0234u;

/* ddi.dll sub_FC4E38 @0xFC4F04 li $t0, 0x81; @0xFC4F38 sw $t0, 4($v0). */
constexpr uint32_t kBlitOpCopy = 0x81u;

/* VR4102 UM ch.5 p131 "(3) kseg1": references are not mapped through TLB and the
   physical address is the virtual address minus 0xA0000000. */
constexpr uint32_t kPaMask = 0x1FFFFFFFu;

}  /* namespace */

void CasioCassiopeiaEm500Display::Init(CerfEmulator& emu) {
    emu_ = &emu;
    fb_.assign(kFbSize, 0u);
}

bool CasioCassiopeiaEm500Display::TryReadByte(uint32_t off, uint8_t& out) {
    if (!InFb(off)) return false;
    out = fb_[off - kFbOffset];
    return true;
}

bool CasioCassiopeiaEm500Display::TryReadHalf(uint32_t off, uint16_t& out) {
    if (!InFb(off)) return false;
    std::memcpy(&out, &fb_[off - kFbOffset], sizeof(out));
    return true;
}

bool CasioCassiopeiaEm500Display::TryReadWord(uint32_t off, uint32_t& out) {
    if (InFb(off)) {
        std::memcpy(&out, &fb_[off - kFbOffset], sizeof(out));
        return true;
    }
    /* ddi.dll sub_FC4E38 @0xFC4F08 lw 0($v0); @0xFC4F10 beqz loc_FC4F24;
       @0xFC4F18 lw 0($v0); @0xFC4F1C bnezl loc_FC4F1C. */
    if (off == kOffBlitGo) { out = 0u; return true; }
    /* ddi.dll sub_FC48A0 @0xFC4954 lw 0x34($a3); @0xFC4958 andi 1; @0xFC4964 lw
       0x34($a3); @0xFC4968 andi 1; @0xFC496C bnezl loc_FC4968. */
    if (off == kOffFillGo) { out = 0u; return true; }
    /* touch.dll loc_F91958 @0xF9199A (lw 0x980; beqz -> bail). */
    if (off == kOffPanelEnable) { out = reg_0980_; return true; }
    /* ddi.dll @0xFC80E0 li $v1, 0xFFFFFFFE; @0xFC80F4 lw $t9, 0x14($v0); @0xFC80FC
       and $t0, $t9, $v1; @0xFC8100 sw $t0, 0x14($v0). nk_main_kernel.exe
       @0x9F0344FC li $t4, 1 -> @0x9F034504 sw 0xAA000994; @0x9F038B4C li $t1, 0 ->
       @0x9F038B58 sw $t1, 0xAA000994. */
    if (off == kOffPanel0994) { out = reg_0994_; return true; }
    return false;
}

bool CasioCassiopeiaEm500Display::TryWriteByte(uint32_t off, uint8_t value) {
    if (!InFb(off)) return false;
    fb_[off - kFbOffset] = value;
    return true;
}

bool CasioCassiopeiaEm500Display::TryWriteHalf(uint32_t off, uint16_t value) {
    if (!InFb(off)) return false;
    std::memcpy(&fb_[off - kFbOffset], &value, sizeof(value));
    return true;
}

bool CasioCassiopeiaEm500Display::TryWriteWord(uint32_t off, uint32_t value) {
    if (InFb(off)) {
        std::memcpy(&fb_[off - kFbOffset], &value, sizeof(value));
        return true;
    }
    switch (off) {
        case kOffPanelEnable: reg_0980_ = value; MaybePublishDisplaySize(); return true;
        case kOffPanel0984:   reg_0984_ = value; return true;
        case kOffPanel0988:   reg_0988_ = value; return true;
        case kOffBrightness:  reg_098C_ = value; return true;
        case kOffPanel0994:   reg_0994_ = value; return true;
        case kOffContrast:    reg_099C_ = value; return true;
        case kOffPanel0998:   return true;
        case kOffBlitOp:      blit_op_        = value; return true;
        case kOffBlitLen:     blit_len_words_ = value; return true;
        case kOffBlitSrc:     blit_src_       = value; return true;
        case kOffBlitDst:     blit_dst_       = value; return true;
        case kOffFillCmd:     fill_cmd_    = value; return true;
        case kOffFillColor:   fill_color_  = value; return true;
        case kOffFillWidth:   fill_w_      = value; return true;
        case kOffFillHeight:  fill_h_      = value; return true;
        case kOffFillDstLo:   fill_dst_lo_ = value; return true;
        case kOffFillDstHi:   fill_dst_hi_ = value; return true;
        case kOffFillGo:
            /* ddi.dll sub_FC48A0 @0xFC4960: only 1 is written to GO. */
            if (value != 1u) {
                LOG(Caution, "EM-500 display fill GO value 0x%X\n", value);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            RunFill();
            return true;
        case kOffBlitGo:
            /* ddi.dll sub_FC4E38 @0xFC4F00 li $t1, 1; @0xFC4F3C sw $t1, 0($v0). */
            if (value != 1u) {
                LOG(Caution, "EM-500 display blit GO value 0x%X\n", value);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            RunBlit();
            return true;
        default: return false;
    }
}

void CasioCassiopeiaEm500Display::RunBlit() {
    if (blit_op_ != kBlitOpCopy) {
        LOG(Caution, "EM-500 display blit opcode 0x%X unsupported\n", blit_op_);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const uint32_t bytes = blit_len_words_ * 4u;
    if (bytes == 0u) return;
    const uint32_t src_pa = blit_src_ & kPaMask;
    if (static_cast<uint64_t>(blit_dst_) + bytes > kFbSize) {
        LOG(Caution, "EM-500 display blit dst=0x%X len=%u exceeds framebuffer\n",
            blit_dst_, bytes);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    uint8_t* host_src = emu_->Get<EmulatedMemory>().TryTranslate(src_pa);
    if (!host_src) {
        LOG(Caution, "EM-500 display blit src_pa=0x%X unbacked\n", src_pa);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    std::memcpy(fb_.data() + blit_dst_, host_src, bytes);
}

void CasioCassiopeiaEm500Display::RunFill() {
    if (fill_cmd_ != 0u) {
        LOG(Caution, "EM-500 display fill cmd 0x%X unsupported\n", fill_cmd_);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const uint32_t w = fill_w_;
    const uint32_t h = fill_h_;
    if (w == 0u || h == 0u) return;
    /* ddi.dll sub_FC48A0 @0xFC48C4: v5 = surfBase(a2[1][8]) + (top<<9) + 2*left -> 0x210(lo)/0x214(hi). */
    const uint32_t fb_off = (fill_dst_hi_ << 16) | (fill_dst_lo_ & 0xFFFFu);
    const uint16_t color  = static_cast<uint16_t>(fill_color_ & 0xFFFFu);
    const uint64_t last = static_cast<uint64_t>(h - 1u) * StrideBytes()
                        + static_cast<uint64_t>(w) * 2u;
    if (static_cast<uint64_t>(fb_off) + last > kFbSize) {
        LOG(Caution, "EM-500 display fill off=0x%X w=%u h=%u exceeds framebuffer\n",
            fb_off, w, h);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    for (uint32_t row = 0; row < h; ++row) {
        uint8_t* p = fb_.data() + fb_off + row * StrideBytes();
        for (uint32_t col = 0; col < w; ++col)
            std::memcpy(p + col * 2u, &color, sizeof(color));
    }
}

void CasioCassiopeiaEm500Display::MaybePublishDisplaySize() {
    size_latch_.PublishOnce(*emu_, IsDisplayEnabled());
}

void CasioCassiopeiaEm500Display::SaveState(StateWriter& w) const {
    w.Write<uint64_t>(fb_.size());
    if (!fb_.empty()) w.WriteBytes(fb_.data(), fb_.size());
    w.Write(blit_op_); w.Write(blit_len_words_);
    w.Write(blit_src_); w.Write(blit_dst_);
    w.Write(fill_dst_lo_); w.Write(fill_dst_hi_);
    w.Write(fill_w_); w.Write(fill_h_); w.Write(fill_color_); w.Write(fill_cmd_);
    w.Write(reg_0980_); w.Write(reg_0984_); w.Write(reg_0988_);
    w.Write(reg_098C_); w.Write(reg_0994_); w.Write(reg_099C_);
    size_latch_.SaveState(w);
}

void CasioCassiopeiaEm500Display::RestoreState(StateReader& r) {
    uint64_t n = 0;
    r.Read(n);
    if (n != kFbSize) {
        emu_->Get<Fatal>().Die("CasioCassiopeiaEm500Display::RestoreState: framebuffer is %llu "
                               "bytes, expected %u", static_cast<unsigned long long>(n), kFbSize);
    }
    fb_.assign(kFbSize, 0u);
    r.ReadBytes(fb_.data(), fb_.size());
    r.Read(blit_op_); r.Read(blit_len_words_);
    r.Read(blit_src_); r.Read(blit_dst_);
    r.Read(fill_dst_lo_); r.Read(fill_dst_hi_);
    r.Read(fill_w_); r.Read(fill_h_); r.Read(fill_color_); r.Read(fill_cmd_);
    r.Read(reg_0980_); r.Read(reg_0984_); r.Read(reg_0988_);
    r.Read(reg_098C_); r.Read(reg_0994_); r.Read(reg_099C_);
    size_latch_.RestoreState(r);
}
