#include "frame_renderer.h"
#include "guest_additions_frame_renderer.h"
#include "panel_frame_renderer.h"
#include "../core/cerf_emulator.h"
#include "../core/fatal.h"

#include <intrin.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

namespace {

constexpr uint32_t kMaxBoxPixels = 0x00FFFFFFu;

class PresentedFrameRenderer : public FrameRenderer {
public:
    using FrameRenderer::FrameRenderer;

    bool HasFrame() override {
        auto* ga = emu_.TryGet<GuestAdditionsFrameRenderer>();
        if (ga && ga->HasFrame()) return true;
        auto* panel = emu_.TryGet<PanelFrameRenderer>();
        return panel && panel->HasFrame();
    }

    void PresentedSize(uint32_t& w, uint32_t& h) override {
        if (auto* ga = emu_.TryGet<GuestAdditionsFrameRenderer>()) {
            ga->PresentedSize(w, h);
            return;
        }
        if (auto* panel = emu_.TryGet<PanelFrameRenderer>()) {
            panel->PresentedSize(w, h);
            return;
        }
        w = 0;
        h = 0;
    }

    void RenderInto(uint32_t* dib_bgra32,
                    uint32_t  width,
                    uint32_t  height) override {
        auto* ga = emu_.TryGet<GuestAdditionsFrameRenderer>();
        if (ga && ga->HasFrame()) {
            ga->RenderInto(dib_bgra32, width, height);
            return;
        }

        auto* panel = emu_.TryGet<PanelFrameRenderer>();
        if (!panel || !panel->HasFrame()) {
            std::memset(dib_bgra32, 0, (size_t)width * height * 4u);
            return;
        }
        if (!ga) {
            panel->RenderInto(dib_bgra32, width, height);
            return;
        }
        ComposeLayer(dib_bgra32, width, height, *panel);
    }

    void RearmContentLatch() override {
        if (auto* ga = emu_.TryGet<GuestAdditionsFrameRenderer>())
            ga->RearmContentLatch();
        if (auto* panel = emu_.TryGet<PanelFrameRenderer>())
            panel->RearmContentLatch();
    }

    std::optional<FbLayout> GetFbLayout() override {
        auto* ga = emu_.TryGet<GuestAdditionsFrameRenderer>();
        if (ga && ga->HasFrame()) return ga->GetFbLayout();
        if (auto* panel = emu_.TryGet<PanelFrameRenderer>())
            return panel->GetFbLayout();
        return std::nullopt;
    }

private:
    void ComposeLayer(uint32_t* dst, uint32_t dst_w, uint32_t dst_h,
                      FrameRenderer& layer) {
        uint32_t lw = 0, lh = 0;
        layer.PresentedSize(lw, lh);
        if (lw == 0 || lh == 0) {
            std::memset(dst, 0, (size_t)dst_w * dst_h * 4u);
            return;
        }
        if (lw == dst_w && lh == dst_h) {
            layer.RenderInto(dst, dst_w, dst_h);
            return;
        }

        if (lw != scratch_w_ || lh != scratch_h_) {
            scratch_.assign((size_t)lw * lh, 0u);
            scratch_w_ = lw;
            scratch_h_ = lh;
        }
        layer.RenderInto(scratch_.data(), lw, lh);

        const uint32_t fit_x = dst_w / lw;
        const uint32_t fit_y = dst_h / lh;
        const uint32_t scale = (fit_x < fit_y) ? fit_x : fit_y;

        std::memset(dst, 0, (size_t)dst_w * dst_h * 4u);

        if (scale == 0) {
            DownscaleLayer(dst, dst_w, dst_h, lw, lh);
            return;
        }

        const uint32_t out_w = lw * scale;
        const uint32_t out_h = lh * scale;
        const uint32_t dst_x = (dst_w - out_w) / 2u;
        const uint32_t dst_y = (dst_h - out_h) / 2u;

        const uint32_t* prev_src_row = nullptr;
        const uint32_t* prev_dst_row = nullptr;
        for (uint32_t y = 0; y < out_h; ++y) {
            const uint32_t* src_row = scratch_.data() + (size_t)(y / scale) * lw;
            uint32_t* dst_row = dst + (size_t)(dst_y + y) * dst_w + dst_x;
            if (src_row == prev_src_row) {
                std::memcpy(dst_row, prev_dst_row, (size_t)out_w * 4u);
                continue;
            }
            if (scale == 1u) {
                std::memcpy(dst_row, src_row, (size_t)out_w * 4u);
            } else {
                for (uint32_t x = 0; x < out_w; ++x)
                    dst_row[x] = src_row[x / scale];
            }
            prev_src_row = src_row;
            prev_dst_row = dst_row;
        }
    }

    void DownscaleLayer(uint32_t* dst, uint32_t dst_w, uint32_t dst_h,
                        uint32_t lw, uint32_t lh) {
        uint32_t out_w, out_h;
        if ((uint64_t)dst_w * lh <= (uint64_t)dst_h * lw) {
            out_w = dst_w;
            out_h = (uint32_t)(((uint64_t)lh * dst_w) / lw);
        } else {
            out_h = dst_h;
            out_w = (uint32_t)(((uint64_t)lw * dst_h) / lh);
        }
        if (out_w == 0) out_w = 1;
        if (out_h == 0) out_h = 1;

        const uint32_t w0    = lw / out_w;
        const uint32_t w_rem = lw % out_w;
        const uint32_t h0    = lh / out_h;
        const uint32_t h_rem = lh % out_h;
        const uint64_t max_box = (uint64_t)(w0 + (w_rem != 0u ? 1u : 0u)) *
                                 (h0 + (h_rem != 0u ? 1u : 0u));
        if (max_box > kMaxBoxPixels) {
            emu_.Get<Fatal>().Die(
                "PresentedFrameRenderer: %ux%u layer into %ux%u needs a %llu-pixel box",
                lw, lh, out_w, out_h, (unsigned long long)max_box);
        }

        uint32_t box_n[2][2];
        uint32_t box_inv[2][2];
        for (uint32_t r = 0; r < 2u; ++r) {
            for (uint32_t c = 0; c < 2u; ++c) {
                box_n[r][c]   = (h0 + r) * (w0 + c);
                box_inv[r][c] = 0xFFFFFFFFu / box_n[r][c];
            }
        }

        const uint32_t dst_x = (dst_w - out_w) / 2u;
        const uint32_t dst_y = (dst_h - out_h) / 2u;

        col_x0_.resize((size_t)out_w + 1u);
        uint32_t x0 = 0, x_frac = 0;
        for (uint32_t ox = 0; ox < out_w; ++ox) {
            col_x0_[ox] = x0;
            x0 += w0;
            x_frac += w_rem;
            if (x_frac >= out_w) {
                x_frac -= out_w;
                ++x0;
            }
        }
        col_x0_[out_w] = lw;
        acc_.resize((size_t)out_w * 4u);

        uint32_t y0 = 0, y_frac = 0;
        for (uint32_t oy = 0; oy < out_h; ++oy) {
            uint32_t rows = h0;
            y_frac += h_rem;
            if (y_frac >= out_h) {
                y_frac -= out_h;
                ++rows;
            }
            std::fill(acc_.begin(), acc_.end(), 0u);
            for (uint32_t sy = y0; sy < y0 + rows; ++sy) {
                const uint32_t* src_row = scratch_.data() + (size_t)sy * lw;
                uint32_t* acc = acc_.data();
                for (uint32_t ox = 0; ox < out_w; ++ox, acc += 4) {
                    const uint32_t x1 = col_x0_[ox + 1u];
                    for (uint32_t sx = col_x0_[ox]; sx < x1; ++sx) {
                        const uint32_t p = src_row[sx];
                        acc[0] += p & 0xFFu;
                        acc[1] += (p >> 8) & 0xFFu;
                        acc[2] += (p >> 16) & 0xFFu;
                        acc[3] += p >> 24;
                    }
                }
            }
            const uint32_t* n_row   = box_n[rows - h0];
            const uint32_t* inv_row = box_inv[rows - h0];
            const uint32_t* acc     = acc_.data();
            uint32_t* dst_row = dst + (size_t)(dst_y + oy) * dst_w + dst_x;
            for (uint32_t ox = 0; ox < out_w; ++ox, acc += 4) {
                const uint32_t c   = col_x0_[ox + 1u] - col_x0_[ox] - w0;
                const uint32_t n   = n_row[c];
                const uint32_t inv = inv_row[c];
                dst_row[ox] = BoxMean(acc[0], n, inv) |
                              (BoxMean(acc[1], n, inv) << 8) |
                              (BoxMean(acc[2], n, inv) << 16) |
                              (BoxMean(acc[3], n, inv) << 24);
            }
            y0 += rows;
        }
    }

    static uint32_t BoxMean(uint32_t sum, uint32_t n, uint32_t inv) {
        const uint32_t x = sum + n / 2u;
        uint32_t q = (uint32_t)(__emulu(x, inv) >> 32);
        if ((q + 1u) * n <= x) ++q;
        return q;
    }

    std::vector<uint32_t> scratch_;
    uint32_t scratch_w_ = 0;
    uint32_t scratch_h_ = 0;
    std::vector<uint32_t> col_x0_;
    std::vector<uint32_t> acc_;
};

}

REGISTER_SERVICE_AS(PresentedFrameRenderer, FrameRenderer);
