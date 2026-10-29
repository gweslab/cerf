#pragma once

#include "viewport_layout.h"

#include <cerfcore/host/frame_source.h>

#include <QColor>
#include <QImage>
#include <QTimer>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

class QPainter;

namespace cerfcore {
class CerfEmulator;
}

class QtPresentHooks {
public:
    virtual ~QtPresentHooks() = default;

    virtual void OnPresentTick(cerfcore::CerfEmulator&, bool) {}
    virtual bool RenderAlt(cerfcore::CerfEmulator&, uint32_t*, int, int, qreal) { return false; }
    virtual bool ShouldDesaturate(cerfcore::CerfEmulator&) { return false; }
    virtual void RenderOverlay(cerfcore::CerfEmulator&, QImage&, int, int, qreal) {}
};

class QtFramePresenter {
public:
    QtFramePresenter(std::unique_ptr<QtPresentHooks> hooks, uint32_t surf_w, uint32_t surf_h, QColor background);

    cerffrontend::ViewportLayout&       Layout() { return layout_; }
    const cerffrontend::ViewportLayout& Layout() const { return layout_; }

    void SetHooks(std::unique_ptr<QtPresentHooks> hooks) { hooks_ = std::move(hooks); }
    bool SetGuestSurfaceSize(uint32_t w, uint32_t h);
    void SetCanvasSize(int w, int h);
    bool Capture(cerfcore::FrameSource& source, std::vector<uint32_t>& out, uint32_t& w, uint32_t& h);
    void DrawTo(cerfcore::CerfEmulator& emu, cerfcore::FrameSource& source, QPainter& painter, int visible_w,
                int visible_h, qreal dpr);
    void StartRepaints(int interval_ms, std::function<void()> repaint);

private:
    const QImage& Present(cerfcore::CerfEmulator& emu, cerfcore::FrameSource& source, int visible_w,
                          int visible_h, qreal dpr);
    bool          ComposeInto(cerfcore::FrameSource& source);
    static void   ForceOpaque(uint32_t* pixels, size_t count);

    std::unique_ptr<QtPresentHooks> hooks_;
    QColor                          background_;
    cerffrontend::ViewportLayout    layout_;
    QImage                          guest_;
    QImage                          present_;
    QTimer                          repaint_timer_;
};
