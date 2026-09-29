#include "imx31_ipu_cpm.h"

#include "../../boards/board_context.h"
#include "imx31_id.h"
#include "../../core/cerf_emulator.h"
#include "../../state/state_stream.h"

namespace {
constexpr uint8_t kImaMemChannelParam = 0x1u;
}

bool Imx31IpuCpm::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Imx31;
}

void Imx31IpuCpm::WriteImaAddr(uint32_t value) {
    std::lock_guard<std::mutex> lk(mtx_);
    ima_mem_nu_  = static_cast<uint8_t> ((value >> 16) & 0xFu);
    ima_row_nu_  = static_cast<uint16_t>((value >>  3) & 0x1FFFu);
    ima_word_nu_ = static_cast<uint8_t> ( value        & 0x7u);
}

uint32_t Imx31IpuCpm::WriteImaData(uint32_t value) {
    std::lock_guard<std::mutex> lk(mtx_);
    uint32_t channel = kNoChannel;
    if (ima_mem_nu_ == kImaMemChannelParam && ima_row_nu_ < kRows &&
        ima_word_nu_ < kDwordsPerRow) {
        cpm_[ima_row_nu_ * kDwordsPerRow + ima_word_nu_] = value;
        channel = ima_row_nu_ >> 1;
    }
    /* §44.3.3.1.9 (PDF p2034): WORD_NU auto-increments per write to
       IMA_DATA; on overflow ROW_NU advances and WORD_NU resets. */
    uint8_t max_word_nu = kDwordsPerRow - 1u;
    if (ima_mem_nu_ != kImaMemChannelParam) max_word_nu = 0;
    if (ima_word_nu_ >= max_word_nu) {
        ima_word_nu_ = 0;
        ++ima_row_nu_;
    } else {
        ++ima_word_nu_;
    }
    return channel;
}

uint32_t Imx31IpuCpm::ExtractBits(const uint32_t* dwords, uint32_t lsb, uint32_t width) {
    const uint32_t dword_idx    = lsb / 32u;
    const uint32_t bit_in_dword = lsb % 32u;
    if (dword_idx >= kDwordsPerRow) return 0;
    uint64_t combined = static_cast<uint64_t>(dwords[dword_idx]);
    if (bit_in_dword + width > 32u && dword_idx + 1u < kDwordsPerRow) {
        combined |= static_cast<uint64_t>(dwords[dword_idx + 1u]) << 32;
    }
    return static_cast<uint32_t>((combined >> bit_in_dword) & ((1ull << width) - 1ull));
}

Imx31IpuCpm::ChannelFormat Imx31IpuCpm::Decode(uint32_t channel) const {
    std::lock_guard<std::mutex> lk(mtx_);
    ChannelFormat f;
    if (channel >= kRows / 2u) return f;
    const uint32_t* w0 = &cpm_[(2u * channel)      * kDwordsPerRow];
    const uint32_t* w1 = &cpm_[(2u * channel + 1u) * kDwordsPerRow];

    /* §44.4 Table 44-29..33 Word0: FW W0[119:108], FH W0[131:120]
       (frame width / height minus 1, in pixels / rows). */
    f.fw = static_cast<uint16_t>(ExtractBits(w0, 108, 12) + 1u);
    f.fh = static_cast<uint16_t>(ExtractBits(w0, 120, 12) + 1u);

    switch (ExtractBits(w1, 64, 3)) {
    case 0: f.bpp_bits = 32; break;
    case 1: f.bpp_bits = 24; break;
    case 2: f.bpp_bits = 16; break;
    case 3: f.bpp_bits =  8; break;
    case 4: f.bpp_bits =  4; break;
    case 5: f.bpp_bits =  1; break;
    default: f.bpp_bits = 0; break;
    }

    f.stride = static_cast<uint16_t>(ExtractBits(w1, 67, 14) + 1u);

    switch (ExtractBits(w1, 81, 3)) {
    case 4: f.pfs = PfsKind::RgbPack; break;
    case 6: f.pfs = PfsKind::Yuv422;  break;
    case 7: f.pfs = PfsKind::Generic; break;
    default: f.pfs = PfsKind::Unknown; break;
    }

    f.ofs[0] = 0;
    f.ofs[1] = static_cast<uint8_t>(ExtractBits(w1, 104, 5));
    f.ofs[2] = static_cast<uint8_t>(ExtractBits(w1, 109, 5));
    f.ofs[3] = static_cast<uint8_t>(ExtractBits(w1, 114, 5));
    f.wid[0] = static_cast<uint8_t>(ExtractBits(w1, 119, 3) + 1u);
    f.wid[1] = static_cast<uint8_t>(ExtractBits(w1, 122, 3) + 1u);
    f.wid[2] = static_cast<uint8_t>(ExtractBits(w1, 125, 3) + 1u);
    f.wid[3] = static_cast<uint8_t>(ExtractBits(w1, 128, 3) + 1u);
    return f;
}

uint32_t Imx31IpuCpm::Eba0(uint32_t channel) const {
    if (channel >= kRows / 2u) return 0;
    std::lock_guard<std::mutex> lk(mtx_);
    return cpm_[(2u * channel + 1u) * kDwordsPerRow];
}

void Imx31IpuCpm::EncodeRgb565(uint32_t channel, uint32_t fb_pa, uint32_t w, uint32_t h) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto set = [](uint32_t* row, uint32_t lsb, uint32_t width, uint32_t val) {
        for (uint32_t i = 0; i < width; ++i)
            if ((val >> i) & 1u) row[(lsb + i) / 32u] |= 1u << ((lsb + i) % 32u);
    };
    uint32_t* w0 = &cpm_[(2u * channel)      * kDwordsPerRow];
    uint32_t* w1 = &cpm_[(2u * channel + 1u) * kDwordsPerRow];
    for (uint32_t i = 0; i < kDwordsPerRow; ++i) { w0[i] = 0u; w1[i] = 0u; }
    set(w0, 108, 12, w - 1u);
    set(w0, 120, 12, h - 1u);
    w1[0] = fb_pa;
    set(w1,  64,  3, 2u);
    set(w1,  67, 14, w * 2u - 1u);
    set(w1,  81,  3, 4u);
    set(w1, 104,  5, 5u);
    set(w1, 109,  5, 11u);
    set(w1, 119,  3, 5u - 1u);
    set(w1, 122,  3, 6u - 1u);
    set(w1, 125,  3, 5u - 1u);
}

void Imx31IpuCpm::Reset() {
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto& v : cpm_) v = 0u;
    ima_mem_nu_  = 0;
    ima_row_nu_  = 0;
    ima_word_nu_ = 0;
}

void Imx31IpuCpm::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mtx_);
    w.WriteBytes("cpm", cpm_, sizeof(cpm_));
    w.Write("ima_mem_nu", ima_mem_nu_);
    w.Write("ima_row_nu", ima_row_nu_);
    w.Write("ima_word_nu", ima_word_nu_);
}

void Imx31IpuCpm::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    r.ReadBytes("cpm", cpm_, sizeof(cpm_));
    r.Read("ima_mem_nu", ima_mem_nu_);
    r.Read("ima_row_nu", ima_row_nu_);
    r.Read("ima_word_nu", ima_word_nu_);
}

REGISTER_SERVICE(Imx31IpuCpm);
