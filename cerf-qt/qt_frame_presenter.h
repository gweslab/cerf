#pragma once

#include "qt_frame_glow.h"
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
    virtual void OnUiTick(cerfcore::CerfEmulator&) {}
    virtual bool RenderAlt(cerfcore::CerfEmulator&, uint32_t*, int, int, qreal) { return false; }
    virtual bool   ShouldDesaturate(cerfcore::CerfEmulator&) { return false; }
    virtual double GlowReach(cerfcore::CerfEmulator&, const cerffrontend::ViewportLayout::Layout&) { return 0.0; }
    virtual void RenderFrameOverlay(cerfcore::CerfEmulator&, QImage&, const cerffrontend::ViewportLayout::Layout&,
                                    qreal) {}
    virtual void RenderOverlay(cerfcore::CerfEmulator&, QImage&, int, int, qreal) {}
};

class QtFramePresenter {
public:
    QtFramePresenter(std::unique_ptr<QtPresentHooks> hooks, uint32_t surf_w, uint32_t surf_h, QColor background);

    cerffrontend::ViewportLayout&       Layout() { return layout_; }
    const cerffrontend::ViewportLayout& Layout() const { return layout_; }

    bool SetGuestSurfaceSize(uint32_t w, uint32_t h);
    void SetCanvasSize(int w, int h);
    bool Capture(cerfcore::FrameSource& source, std::vector<uint32_t>& out, uint32_t& w, uint32_t& h);
    void DrawTo(cerfcore::CerfEmulator& emu, cerfcore::FrameSource& source, QPainter& painter, int visible_w,
                int visible_h, qreal dpr);
    void StartRepaints(int interval_ms, std::function<void()> repaint);
    void UiTick(cerfcore::CerfEmulator& emu);

private:
    const QImage& Present(cerfcore::CerfEmulator& emu, cerfcore::FrameSource& source, int visible_w,
                          int visible_h, qreal dpr);
    bool          ComposeInto(cerfcore::CerfEmulator& emu, cerfcore::FrameSource& source);
    static void   ForceOpaque(uint32_t* pixels, size_t count);

    std::unique_ptr<QtPresentHooks> hooks_;
    QColor                          background_;
    cerffrontend::ViewportLayout    layout_;
    QImage                          guest_;
    QImage                          present_;
    QtFrameGlow                     glow_;
    QTimer                          repaint_timer_;
};
