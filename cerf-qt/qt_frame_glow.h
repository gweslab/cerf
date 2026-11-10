#pragma once

#include <QColor>
#include <QImage>
#include <QTransform>

class QtFrameGlow {
public:
    bool Shows(double fit_zoom) const;
    void Compose(QImage& target, const QImage& guest, const QTransform& turn, int target_w, int target_h,
                 int reach_px, double fit_zoom, QColor background);

private:
    bool Spread(const QImage& guest, int target_w, int target_h, int reach_px, double fit_zoom, QColor background);
    void Paint(const QImage& target, const QTransform& turn, int target_w, int target_h, QColor background);

    QImage     cells_;
    QImage     spread_;
    QImage     shown_spread_;
    QImage     layer_;
    QTransform shown_turn_;
    int        shown_w_     = 0;
    int        shown_h_     = 0;
    int        reach_cells_ = 0;
    double     cell_w_      = 0.0;
    double     cell_h_      = 0.0;
};
