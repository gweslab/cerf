#include "qt_frame_glow.h"

#include <QPainter>
#include <QRegion>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <utility>

namespace {

constexpr int    kCellsShort    = 8;
constexpr int    kMinReachCells = 6;
constexpr int    kBlurBaseCells = 1;
constexpr double kEdgeLevel     = 0.375;
constexpr double kFadedZoom     = 0.8;
constexpr double kFadedCover    = 0.5;
constexpr double kFullCover     = 0.6;

int Mix(int from, int to, double level) { return static_cast<int>(std::lround(from + (to - from) * level)); }

int Outside(int index, int reach, int core) { return std::max({0, reach - index, index - (reach + core - 1)}); }

double Ramp(double value, double faded, double full) {
    return std::clamp((value - faded) / (full - faded), 0.0, 1.0);
}

}

double QtFrameGlow::Strength(double fit_zoom, double cover_zoom) const {
    return std::min(Ramp(fit_zoom, kFadedZoom, 1.0), Ramp(cover_zoom, kFadedCover, kFullCover));
}

void QtFrameGlow::Compose(QImage& target, const QImage& guest, const QTransform& turn, int target_w, int target_h,
                          int reach_px, double strength, QColor background) {
    if (!Spread(guest, target_w, target_h, reach_px, strength, background)) {
        target.fill(background);
        return;
    }
    if (layer_.size() != target.size() || spread_ != shown_spread_ || turn != shown_turn_ || target_w != shown_w_ ||
        target_h != shown_h_) {
        std::swap(spread_, shown_spread_);
        shown_turn_ = turn;
        shown_w_    = target_w;
        shown_h_    = target_h;
        Paint(target, turn, target_w, target_h, background);
    }
    std::memcpy(target.bits(), layer_.constBits(), static_cast<size_t>(layer_.sizeInBytes()));
}

bool QtFrameGlow::Spread(const QImage& guest, int target_w, int target_h, int reach_px, double strength,
                         QColor background) {
    if (reach_px <= 0) return false;
    const double cell = std::min(target_w, target_h) / static_cast<double>(kCellsShort);
    const int    gw   = static_cast<int>(std::lround(target_w / cell));
    const int    gh   = static_cast<int>(std::lround(target_h / cell));
    cells_ = guest.scaled(gw, gh, Qt::IgnoreAspectRatio, Qt::SmoothTransformation)
                 .convertToFormat(QImage::Format_RGB32);

    const int reach = std::max(kMinReachCells, static_cast<int>(std::ceil(reach_px / cell)));
    Extend(reach, gw, gh);
    BlurAlongEdges(reach, gw, gh);

    const int sw = gw + 2 * reach;
    const int sh = gh + 2 * reach;
    if (spread_.width() != sw || spread_.height() != sh) spread_ = QImage(sw, sh, QImage::Format_RGB32);
    const int    bg_r = background.red();
    const int    bg_g = background.green();
    const int    bg_b = background.blue();
    const double edge = kEdgeLevel * strength;
    for (int y = 0; y < sh; ++y) {
        auto*        row    = reinterpret_cast<QRgb*>(spread_.scanLine(y));
        const Light* lights = &lights_[static_cast<size_t>(y) * sw];
        const int    dy     = Outside(y, reach, gh);
        for (int x = 0; x < sw; ++x) {
            const int    dx    = Outside(x, reach, gw);
            const double away  = std::sqrt(static_cast<double>(dx * dx + dy * dy));
            const double level = edge * std::max(0.0, 1.0 - away / reach);
            row[x]             = qRgb(Mix(bg_r, lights[x].r, level), Mix(bg_g, lights[x].g, level),
                                      Mix(bg_b, lights[x].b, level));
        }
    }
    reach_cells_ = reach;
    cell_w_      = static_cast<double>(target_w) / gw;
    cell_h_      = static_cast<double>(target_h) / gh;
    return true;
}

void QtFrameGlow::Extend(int reach, int gw, int gh) {
    const int sw = gw + 2 * reach;
    const int sh = gh + 2 * reach;
    lights_.resize(static_cast<size_t>(sw) * sh);
    for (int y = 0; y < sh; ++y) {
        const auto* cells_row = reinterpret_cast<const QRgb*>(cells_.constScanLine(std::clamp(y - reach, 0, gh - 1)));
        Light*      lights    = &lights_[static_cast<size_t>(y) * sw];
        for (int x = 0; x < sw; ++x) {
            const QRgb c = cells_row[std::clamp(x - reach, 0, gw - 1)];
            lights[x]    = {qRed(c), qGreen(c), qBlue(c)};
        }
    }
}

void QtFrameGlow::BlurAlongEdges(int reach, int gw, int gh) {
    const int sw = gw + 2 * reach;
    const int sh = gh + 2 * reach;
    line_.resize(static_cast<size_t>(sw));
    for (int y = 0; y < sh; ++y) {
        const int dy = Outside(y, reach, gh);
        if (dy == 0) continue;
        Light* row = &lights_[static_cast<size_t>(y) * sw];
        std::copy(row, row + sw, line_.begin());
        BlurLine(kBlurBaseCells + dy);
        std::copy(line_.begin(), line_.end(), row);
    }
    line_.resize(static_cast<size_t>(sh));
    for (int x = 0; x < sw; ++x) {
        const int dx = Outside(x, reach, gw);
        if (dx == 0) continue;
        for (int y = 0; y < sh; ++y) line_[static_cast<size_t>(y)] = lights_[static_cast<size_t>(y) * sw + x];
        BlurLine(kBlurBaseCells + dx);
        for (int y = 0; y < sh; ++y) lights_[static_cast<size_t>(y) * sw + x] = line_[static_cast<size_t>(y)];
    }
}

void QtFrameGlow::BlurLine(int radius) {
    const int n = static_cast<int>(line_.size());
    sums_.resize(line_.size() + 1);
    sums_[0] = Light{};
    for (int i = 0; i < n; ++i) {
        const Light& v = line_[static_cast<size_t>(i)];
        const Light& s = sums_[static_cast<size_t>(i)];
        sums_[static_cast<size_t>(i) + 1] = {s.r + v.r, s.g + v.g, s.b + v.b};
    }
    for (int i = 0; i < n; ++i) {
        const int    lo    = std::max(0, i - radius);
        const int    hi    = std::min(n, i + radius + 1);
        const int    count = hi - lo;
        const Light& top   = sums_[static_cast<size_t>(hi)];
        const Light& base  = sums_[static_cast<size_t>(lo)];
        line_[static_cast<size_t>(i)] = {(top.r - base.r + count / 2) / count, (top.g - base.g + count / 2) / count,
                                         (top.b - base.b + count / 2) / count};
    }
}

void QtFrameGlow::Paint(const QImage& target, const QTransform& turn, int target_w, int target_h, QColor background) {
    if (layer_.size() != target.size()) layer_ = QImage(target.size(), QImage::Format_RGB32);
    layer_.fill(background);
    const QRectF outer(-reach_cells_ * cell_w_, -reach_cells_ * cell_h_, target_w + 2 * reach_cells_ * cell_w_,
                       target_h + 2 * reach_cells_ * cell_h_);
    QPainter p(&layer_);
    p.setTransform(turn);
    p.setRenderHint(QPainter::SmoothPixmapTransform, true);
    p.setClipRegion(QRegion(outer.toAlignedRect()) - QRegion(0, 0, target_w, target_h));
    p.drawImage(outer, shown_spread_);
}
