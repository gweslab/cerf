#pragma once

#include <QColor>
#include <QImage>
#include <QRectF>

#include <cstdint>
#include <vector>

class QtFrameGlow {
public:
    double Strength(double fit_zoom, double cover_zoom) const;
    bool   Update(const QImage& guest, int target_w, int target_h, int reach_px, double strength, QColor background);

    const QImage& Image() const { return shown_; }
    QRectF        Rect(int target_w, int target_h) const;
    uint64_t      Generation() const { return generation_; }

private:
    struct Light {
        int r = 0;
        int g = 0;
        int b = 0;
    };

    void Spread(const QImage& guest, int target_w, int target_h, int reach_px, double strength, QColor background);
    void Extend(int reach, int gw, int gh);
    void BlurAlongEdges(int reach, int gw, int gh);
    void BlurLine(int radius);

    QImage             cells_;
    std::vector<Light> lights_;
    std::vector<Light> line_;
    std::vector<Light> sums_;
    QImage             spread_;
    QImage             shown_;
    uint64_t           generation_  = 0;
    int                reach_cells_ = 0;
    double             cell_w_      = 0.0;
    double             cell_h_      = 0.0;
};
