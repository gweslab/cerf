#pragma once

namespace cerfcore {
struct DbHud;
}

namespace cerffrontend {

struct ContentBox {
    double left   = 0.0;
    double top    = 0.0;
    double right  = 1.0;
    double bottom = 1.0;

    double Width() const { return right - left; }
    double Height() const { return bottom - top; }
    bool   operator==(const ContentBox&) const = default;
};

struct ContentFrame {
    const cerfcore::DbHud* hud = nullptr;

    ContentBox Box(double width, double height) const;
    void       SurfaceFor(double content_w, double content_h, double& surface_w, double& surface_h) const;
    bool       operator==(const ContentFrame&) const = default;
};

struct ViewPresentation {
    ContentFrame frame;
    int          quarter = 0;

    ContentBox PresentedBox(double surface_w, double surface_h) const;
    bool       Turned() const { return (quarter & 1) != 0; }
    bool       operator==(const ViewPresentation&) const = default;
};

struct FramePoint {
    double x = 0.0;
    double y = 0.0;
};

struct FrameRect {
    double x = 0.0;
    double y = 0.0;
    double w = 0.0;
    double h = 0.0;

    bool operator==(const FrameRect&) const = default;
};

class FramePlacement {
public:
    FramePlacement(FrameRect presented, int quarter) : presented_(presented), quarter_(quarter & 3) {}

    double DeviceWidth() const { return (quarter_ & 1) ? presented_.h : presented_.w; }
    double DeviceHeight() const { return (quarter_ & 1) ? presented_.w : presented_.h; }
    int    Quarter() const { return quarter_; }

    FramePoint ToCanvas(FramePoint device) const;
    FramePoint ToDevice(FramePoint canvas) const;
    FrameRect  ToCanvas(FrameRect device) const;
    FramePoint TurnDelta(FramePoint canvas_delta) const;

private:
    FrameRect presented_;
    int       quarter_;
};

}
