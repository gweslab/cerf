#pragma once

#include <atomic>
#include <cstdint>

namespace cerffrontend {

enum class ViewportMode { Original, Aspect, Stretch, Integer, Placed };

class ViewportLayout {
public:
    struct Layout {
        int  dst_x = 0, dst_y = 0, dst_w = 0, dst_h = 0;
        int  src_x = 0, src_y = 0, src_w = 0, src_h = 0;
        bool stretch = false;
    };

    struct Scroll {
        bool horizontal = false;
        bool vertical   = false;
        int  content_w  = 0;
        int  content_h  = 0;
        int  page_w     = 0;
        int  page_h     = 0;
        int  pos_x      = 0;
        int  pos_y      = 0;
    };

    static constexpr int kScrollLineStep = 16;

    uint32_t SurfaceWidth() const { return surface_w_.load(std::memory_order_acquire); }
    uint32_t SurfaceHeight() const { return surface_h_.load(std::memory_order_acquire); }
    void     SetSurfaceSize(uint32_t w, uint32_t h);

    void SetCanvasSize(int w, int h);
    int  CanvasWidth() const { return canvas_w_; }
    int  CanvasHeight() const { return canvas_h_; }

    int ContentWidth() const;
    int ContentHeight() const;

    ViewportMode Mode() const { return mode_; }
    bool         Antialias() const { return antialias_; }
    int          IntegerFactor() const { return integer_factor_; }
    bool         SetMode(ViewportMode m);
    bool         SetAntialias(bool on);
    bool         SetIntegerScale(int factor);
    bool         SetPlacement(double scale, double x, double y);

    bool Active() const { return active_; }
    bool SetActive(bool active);

    Layout Compute() const;
    bool   HostToGuest(int cx, int cy, int& sx, int& sy) const;
    void   ClampGuest(int& sx, int& sy) const;

    Scroll UpdateScroll();
    void   ScrollTo(bool horizontal, int pos);
    int    ScrollPos(bool horizontal) const { return horizontal ? scroll_x_ : scroll_y_; }
    void   ResetScroll() { scroll_x_ = scroll_y_ = 0; }

private:
    std::atomic<uint32_t> surface_w_{0};
    std::atomic<uint32_t> surface_h_{0};
    int                   canvas_w_ = 0;
    int                   canvas_h_ = 0;

    ViewportMode mode_           = ViewportMode::Original;
    int          integer_factor_ = 2;
    bool         antialias_      = false;
    bool         active_         = true;

    int scroll_x_ = 0;
    int scroll_y_ = 0;

    double placed_scale_ = 1.0;
    double placed_x_     = 0.0;
    double placed_y_     = 0.0;
};

}
