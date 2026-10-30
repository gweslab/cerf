#pragma once

#include <QPointF>
#include <QRectF>

#include <cstdint>

enum class ViewMode { FitScreen, FitSafeZone, OriginalScale, FreeForm };

struct Placement {
    double scale = 1.0;
    double x     = 0.0;
    double y     = 0.0;
};

struct ViewArea {
    int width      = 0;
    int height     = 0;
    int left       = 0;
    int top        = 0;
    int right      = 0;
    int bottom     = 0;
    int hud_left   = 0;
    int hud_top    = 0;
    int hud_right  = 0;
    int hud_bottom = 0;

    bool operator==(const ViewArea&) const = default;
};

class ViewPlacement {
public:
    void SetArea(const ViewArea& area);
    void SetSurface(uint32_t width, uint32_t height);

    ViewMode  Mode() const { return mode_; }
    void      SetMode(ViewMode mode);
    Placement Current() const;
    double    SurfaceWidth() const { return surface_w_; }
    double    SurfaceHeight() const { return surface_h_; }
    QRectF    ScreenRegion() const;

    void BeginPinch(QPointF centroid, double distance);
    void UpdatePinch(QPointF centroid, double distance);
    bool PinchLocked() const { return pinch_left_ && mode_ != ViewMode::FreeForm; }

private:
    Placement ForMode(ViewMode mode) const;
    Placement Fit(const QRectF& region) const;
    Placement Centered(double scale) const;
    Placement Moved(const Placement& placement, const ViewArea& from) const;
    bool      Near(const Placement& a, const Placement& b) const;
    bool      NearScale(const Placement& a, const Placement& b) const;

    ViewArea  area_;
    double    surface_w_ = 0.0;
    double    surface_h_ = 0.0;
    ViewMode  mode_      = ViewMode::FitSafeZone;
    Placement free_;
    Placement pinch_base_;
    QPointF   pinch_centroid_;
    double    pinch_distance_   = 1.0;
    ViewMode  pinch_start_mode_ = ViewMode::FitSafeZone;
    bool      pinch_left_       = false;
};
