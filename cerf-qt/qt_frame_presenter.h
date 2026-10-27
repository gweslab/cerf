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

class QtPresentHooks {
public:
    virtual ~QtPresentHooks() = default;

    virtual void OnPresentTick(bool) {}
    virtual bool RenderAlt(uint32_t*, int, int) { return false; }
    virtual bool ShouldDesaturate() { return false; }
    virtual void RenderOverlay(QImage&, int, int) {}
};

class QtFramePresenter {
public:
    QtFramePresenter(cerfcore::FrameSource& source, std::unique_ptr<QtPresentHooks> hooks, uint32_t surf_w,
                     uint32_t surf_h, QColor background);

    cerffrontend::ViewportLayout&       Layout() { return layout_; }
    const cerffrontend::ViewportLayout& Layout() const { return layout_; }

    bool SetGuestSurfaceSize(uint32_t w, uint32_t h);
    void SetCanvasSize(int w, int h);
    bool Capture(std::vector<uint32_t>& out, uint32_t& w, uint32_t& h);
    void DrawTo(QPainter& painter, int visible_w, int visible_h, qreal dpr);
    void StartRepaints(int interval_ms, std::function<void()> repaint);

private:
    const QImage& Present(int visible_w, int visible_h);
    bool          ComposeInto();
    static void   ForceOpaque(uint32_t* pixels, size_t count);

    cerfcore::FrameSource&          source_;
    std::unique_ptr<QtPresentHooks> hooks_;
    QColor                          background_;
    cerffrontend::ViewportLayout    layout_;
    QImage                          guest_;
    QImage                          present_;
    QTimer                          repaint_timer_;
};
