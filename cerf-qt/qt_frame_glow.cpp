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
constexpr double kEdgeLevel     = 0.6;
constexpr double kFadedZoom     = 0.8;

int Mix(int from, int to, double level) { return static_cast<int>(std::lround(from + (to - from) * level)); }

}

bool QtFrameGlow::Shows(double fit_zoom) const { return fit_zoom > kFadedZoom; }

void QtFrameGlow::Compose(QImage& target, const QImage& guest, const QTransform& turn, int target_w, int target_h,
                          int reach_px, double fit_zoom, QColor background) {
    if (!Spread(guest, target_w, target_h, reach_px, fit_zoom, background)) {
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

bool QtFrameGlow::Spread(const QImage& guest, int target_w, int target_h, int reach_px, double fit_zoom,
                         QColor background) {
    if (reach_px <= 0) return false;
    const double strength = std::clamp((fit_zoom - kFadedZoom) / (1.0 - kFadedZoom), 0.0, 1.0);
    const double cell = std::min(target_w, target_h) / static_cast<double>(kCellsShort);
    const int    gw   = static_cast<int>(std::lround(target_w / cell));
    const int    gh   = static_cast<int>(std::lround(target_h / cell));
    cells_ = guest.scaled(gw, gh, Qt::IgnoreAspectRatio, Qt::SmoothTransformation)
                 .convertToFormat(QImage::Format_RGB32);

    const int reach = std::max(kMinReachCells, static_cast<int>(std::ceil(reach_px / cell)));
    const int sw    = gw + 2 * reach;
    const int sh    = gh + 2 * reach;
    if (spread_.width() != sw || spread_.height() != sh) spread_ = QImage(sw, sh, QImage::Format_RGB32);
    const int    bg_r = background.red();
    const int    bg_g = background.green();
    const int    bg_b = background.blue();
    const double edge = kEdgeLevel * strength;
    for (int y = 0; y < sh; ++y) {
        auto*       row       = reinterpret_cast<QRgb*>(spread_.scanLine(y));
        const int   dy        = std::max({0, reach - y, y - (reach + gh - 1)});
        const int   cy        = std::clamp(y - reach, 0, gh - 1);
        const auto* cells_row = reinterpret_cast<const QRgb*>(cells_.constScanLine(cy));
        for (int x = 0; x < sw; ++x) {
            const int    dx    = std::max({0, reach - x, x - (reach + gw - 1)});
            const double away  = std::sqrt(static_cast<double>(dx * dx + dy * dy));
            const double level = edge * std::max(0.0, 1.0 - away / reach);
            const QRgb   c     = cells_row[std::clamp(x - reach, 0, gw - 1)];
            row[x] = qRgb(Mix(bg_r, qRed(c), level), Mix(bg_g, qGreen(c), level), Mix(bg_b, qBlue(c), level));
        }
    }
    reach_cells_ = reach;
    cell_w_      = static_cast<double>(target_w) / gw;
    cell_h_      = static_cast<double>(target_h) / gh;
    return true;
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
