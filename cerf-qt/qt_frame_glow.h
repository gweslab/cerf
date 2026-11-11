#pragma once

#include <QColor>
#include <QImage>
#include <QTransform>

#include <vector>

class QtFrameGlow {
public:
    double Strength(double fit_zoom, double cover_zoom) const;
    void   Compose(QImage& target, const QImage& guest, const QTransform& turn, int target_w, int target_h,
                   int reach_px, double strength, QColor background);

private:
    struct Light {
        int r = 0;
        int g = 0;
        int b = 0;
    };

    bool Spread(const QImage& guest, int target_w, int target_h, int reach_px, double strength, QColor background);
    void Extend(int reach, int gw, int gh);
    void BlurAlongEdges(int reach, int gw, int gh);
    void BlurLine(int radius);
    void Paint(const QImage& target, const QTransform& turn, int target_w, int target_h, QColor background);

    QImage             cells_;
    std::vector<Light> lights_;
    std::vector<Light> line_;
    std::vector<Light> sums_;
    QImage             spread_;
    QImage             shown_spread_;
    QImage             layer_;
    QTransform         shown_turn_;
    int                shown_w_     = 0;
    int                shown_h_     = 0;
    int                reach_cells_ = 0;
    double             cell_w_      = 0.0;
    double             cell_h_      = 0.0;
};
