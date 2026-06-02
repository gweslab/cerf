#define NOMINMAX

#include "memory_visualizer.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "../cpu/emulated_memory.h"
#include "../jit/arm_mmu.h"
#include "frame_renderer.h"

#include <windowsx.h>

#include <algorithm>
#include <cstdio>

REGISTER_SERVICE(MemoryVisualizer);

namespace {
constexpr uint32_t kUnmapped = 0xFF301030u;  /* dark magenta for non-translatable pages */
constexpr int      kZoomMin  = -16;
constexpr int      kZoomMax  = 8;
}  /* namespace */

MemoryVisualizer::~MemoryVisualizer() {
    if (font_) DeleteObject(font_);
}

bool MemoryVisualizer::ShouldRegister() {
#if CERF_DEV_MODE
    return true;
#else
    return false;
#endif
}

uint32_t MemoryVisualizer::BytesPerSample() const {
    switch (interp_) {
        case Interp::Rgb8888: return 4;
        case Interp::Rgb565:  return 2;
        default:              return 1;  /* Bit1, Gray8 */
    }
}

bool MemoryVisualizer::JumpToFramebuffer() {
    auto* fr = emu_.TryGet<FrameRenderer>();
    if (!fr) return false;
    const auto layout = fr->GetFbLayout();
    if (!layout) {
        LOG(Lcd, "[MEMVIS] active renderer advertises no framebuffer layout\n");
        return false;
    }
    space_        = Space::Pa;  /* framebuffer EBA is a physical address */
    base_pa_      = layout->pa;
    stride_bytes_ = layout->stride_bytes ? layout->stride_bytes : stride_bytes_;
    interp_       = layout->rgb565        ? Interp::Rgb565
                  : layout->bpp_bits == 32 ? Interp::Rgb8888
                  : layout->bpp_bits == 8  ? Interp::Gray8
                                           : Interp::Bit1;
    zoom_ = 0;
    return true;
}

void MemoryVisualizer::RenderInto(HDC dc, uint32_t* dib, uint32_t w, uint32_t h) {
    if (!initialized_ && JumpToFramebuffer()) initialized_ = true;

    auto& mem  = emu_.Get<EmulatedMemory>();
    auto* mmu  = space_ == Space::Va ? emu_.TryGet<ArmMmu>() : nullptr;
    const uint32_t base = space_ == Space::Va ? base_va_ : base_pa_;

    const int scale = zoom_ > 0 ? zoom_ + 1 : 1;
    const int skip  = zoom_ < 0 ? -zoom_ + 1 : 1;

    /* Page-cached read: resolve the containing 4 KB page once and index within
       it. The page resolves to a contiguous host span (PA region backing, or a
       single VA page via PeekVaToHost), so the page pointer is valid for every
       byte in that page. VA mode walks the LIVE on-CPU process's tables. */
    uint32_t       cache_page = 0;
    bool           cache_valid = false;
    const uint8_t* cache_host = nullptr;
    auto rd = [&](uint32_t addr, bool& mapped) -> uint8_t {
        const uint32_t page = addr & ~0xFFFu;
        if (!cache_valid || page != cache_page) {
            cache_host  = space_ == Space::Va
                        ? (mmu ? mmu->PeekVaToHost(page) : nullptr)
                        : mem.TryTranslate(page);
            cache_page  = page;
            cache_valid = true;
        }
        if (!cache_host) { mapped = false; return 0; }
        mapped = true;
        return cache_host[addr - page];
    };

    for (uint32_t y = 0; y < h; ++y) {
        const uint32_t sy     = (y / scale) * skip;
        const uint32_t row_pa = base + sy * stride_bytes_;
        uint32_t*      dst    = dib + (size_t)y * w;
        for (uint32_t x = 0; x < w; ++x) {
            const uint32_t sx = (x / scale) * skip;
            bool m0;
            switch (interp_) {
                case Interp::Bit1: {
                    const uint8_t byte = rd(row_pa + (sx >> 3), m0);
                    dst[x] = !m0 ? kUnmapped
                           : ((byte >> (7u - (sx & 7u))) & 1u) ? 0xFFFFFFFFu
                                                               : 0xFF000000u;
                    break;
                }
                case Interp::Gray8: {
                    const uint8_t v = rd(row_pa + sx, m0);
                    dst[x] = !m0 ? kUnmapped
                                 : (0xFF000000u | (v << 16) | (v << 8) | v);
                    break;
                }
                case Interp::Rgb565: {
                    bool m1;
                    const uint8_t lo = rd(row_pa + sx * 2u,      m0);
                    const uint8_t hi = rd(row_pa + sx * 2u + 1u, m1);
                    if (!m0 || !m1) { dst[x] = kUnmapped; break; }
                    const uint16_t px = (uint16_t)(lo | (hi << 8));
                    const uint8_t  r5 = (px >> 11) & 0x1Fu;
                    const uint8_t  g6 = (px >>  5) & 0x3Fu;
                    const uint8_t  b5 =  px        & 0x1Fu;
                    const uint8_t  r  = (uint8_t)((r5 << 3) | (r5 >> 2));
                    const uint8_t  g  = (uint8_t)((g6 << 2) | (g6 >> 4));
                    const uint8_t  b  = (uint8_t)((b5 << 3) | (b5 >> 2));
                    dst[x] = 0xFF000000u | (r << 16) | (g << 8) | b;
                    break;
                }
                case Interp::Rgb8888: {
                    bool m1, m2;
                    const uint8_t b = rd(row_pa + sx * 4u,      m0);
                    const uint8_t g = rd(row_pa + sx * 4u + 1u, m1);
                    const uint8_t r = rd(row_pa + sx * 4u + 2u, m2);
                    dst[x] = (!m0 || !m1 || !m2) ? kUnmapped
                           : (0xFF000000u | (r << 16) | (g << 8) | b);
                    break;
                }
            }
        }
    }

    DrawOverlay(dc, w, h);
}

void MemoryVisualizer::OnKeyDown(uint8_t vk) {
    const uint32_t bps  = BytesPerSample();
    uint32_t&      base = space_ == Space::Va ? base_va_ : base_pa_;
    switch (vk) {
        case VK_LEFT:  base -= bps;                  break;
        case VK_RIGHT: base += bps;                  break;
        case VK_UP:    base -= stride_bytes_;        break;
        case VK_DOWN:  base += stride_bytes_;        break;
        case VK_PRIOR: base -= stride_bytes_ * 64u;  break;
        case VK_NEXT:  base += stride_bytes_ * 64u;  break;
        case '1': interp_ = Interp::Bit1;    break;
        case '2': interp_ = Interp::Gray8;   break;
        case '3': interp_ = Interp::Rgb565;  break;
        case '4': interp_ = Interp::Rgb8888; break;
        case 'V': space_ = space_ == Space::Va ? Space::Pa : Space::Va; break;
        case VK_OEM_4: if (stride_bytes_ > bps) stride_bytes_ -= bps; break;  /* [ */
        case VK_OEM_6: stride_bytes_ += bps;                          break;  /* ] */
        case VK_OEM_MINUS: zoom_ = std::max(zoom_ - 1, kZoomMin);     break;
        case VK_OEM_PLUS:  zoom_ = std::min(zoom_ + 1, kZoomMax);     break;
        case 'F': JumpToFramebuffer(); break;
        default: break;
    }
}

bool MemoryVisualizer::HandleInput(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_MOUSEWHEEL: {
            const int d = GET_WHEEL_DELTA_WPARAM(wp);
            zoom_ = std::clamp(zoom_ + (d > 0 ? 1 : -1), kZoomMin, kZoomMax);
            return true;
        }
        case WM_LBUTTONDOWN:
            SetFocus(hwnd);
            dragging_     = true;
            drag_x_       = GET_X_LPARAM(lp);
            drag_y_       = GET_Y_LPARAM(lp);
            drag_base_pa_ = base_pa_;
            SetCapture(hwnd);
            return true;
        case WM_MOUSEMOVE: {
            if (!dragging_) return false;
            const int scale = zoom_ > 0 ? zoom_ + 1 : 1;
            const int skip  = zoom_ < 0 ? -zoom_ + 1 : 1;
            const int d_samp = ((GET_X_LPARAM(lp) - drag_x_) / scale) * skip;
            const int d_rows = ((GET_Y_LPARAM(lp) - drag_y_) / scale) * skip;
            base_pa_ = drag_base_pa_ -
                (uint32_t)(d_rows * (int)stride_bytes_ + d_samp * (int)BytesPerSample());
            return true;
        }
        case WM_LBUTTONUP:
            if (dragging_) { dragging_ = false; ReleaseCapture(); }
            return true;
        case WM_CAPTURECHANGED:
            dragging_ = false;
            return true;
        case WM_KEYDOWN:
            OnKeyDown((uint8_t)wp);
            return true;
        default:
            return false;
    }
}

void MemoryVisualizer::CancelInput() {
    dragging_ = false;
}

HFONT MemoryVisualizer::EnsureFont() {
    if (!font_) {
        font_ = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                            CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
    }
    return font_;
}

void MemoryVisualizer::DrawOverlay(HDC dc, uint32_t /*w*/, uint32_t /*h*/) {
    const wchar_t* in = interp_ == Interp::Bit1    ? L"1bpp"
                      : interp_ == Interp::Gray8   ? L"gray8"
                      : interp_ == Interp::Rgb565  ? L"rgb565"
                                                   : L"rgb8888";
    const uint32_t base = space_ == Space::Va ? base_va_ : base_pa_;
    wchar_t l1[200];
    if (space_ == Space::Va) {
        uint32_t pid = 0;
        if (auto* mmu = emu_.TryGet<ArmMmu>()) pid = mmu->State()->process_id;
        swprintf(l1, 200, L"MEM(VA live)  base=0x%08X  stride=%u B  zoom=%d  %s  pid=0x%08X",
                 base, stride_bytes_, zoom_, in, pid);
    } else {
        swprintf(l1, 200, L"MEM(PA)  base=0x%08X  stride=%u B  zoom=%d  %s",
                 base, stride_bytes_, zoom_, in);
    }

    const wchar_t* lines[] = {
        l1,
        L"V = PA / VA-of-live-process       F = jump to framebuffer",
        L"arrows = pan 1 px / row           PgUp/PgDn = pan 64 rows       drag = pan",
        L"mouse wheel or - / + = zoom       [ / ] = narrow / widen stride",
        L"1 = 1bpp   2 = gray8   3 = rgb565   4 = rgb8888",
    };

    SetBkMode(dc, TRANSPARENT);
    HFONT old = (HFONT)SelectObject(dc, EnsureFont());
    for (int i = 0; i < (int)(sizeof(lines) / sizeof(lines[0])); ++i) {
        const int y = 4 + i * 16;
        const int n = (int)wcslen(lines[i]);
        SetTextColor(dc, RGB(0, 0, 0));
        TextOutW(dc, 5, y + 1, lines[i], n);
        SetTextColor(dc, RGB(0, 255, 128));
        TextOutW(dc, 4, y, lines[i], n);
    }
    SelectObject(dc, old);
}
