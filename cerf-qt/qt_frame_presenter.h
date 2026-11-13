#pragma once

#include "frame_layers.h"
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
    virtual bool   OverlayShown(cerfcore::CerfEmulator&) { return false; }
    virtual const ShaderChainSpec* Shaders(cerfcore::CerfEmulator&) { return nullptr; }
    virtual void                   ShadersApplied(cerfcore::CerfEmulator&, const ShaderChainResult&) {}
    virtual void                   ShadedCaptured(cerfcore::CerfEmulator&, const ShadedFrame*) {}
    virtual void RenderFrameOverlay(cerfcore::CerfEmulator&, QImage&, const cerffrontend::ViewportLayout::Layout&,
                                    qreal) {}
    virtual void RenderOverlay(cerfcore::CerfEmulator&, QImage&, int, int, qreal) {}
};

class QtFramePresenter {
public:
    QtFramePresenter(std::unique_ptr<QtPresentHooks> hooks, uint32_t surf_w, uint32_t surf_h, QColor background);

    cerffrontend::ViewportLayout&       Layout() { return layout_; }
    const cerffrontend::ViewportLayout& Layout() const { return layout_; }

    bool               SetGuestSurfaceSize(uint32_t w, uint32_t h);
    void               SetCanvasSize(int w, int h);
    bool               Capture(cerfcore::FrameSource& source, std::vector<uint32_t>& out, uint32_t& w, uint32_t& h);
    const FrameLayers& Present(cerfcore::CerfEmulator& emu, cerfcore::FrameSource& source, int visible_w,
                               int visible_h, qreal dpr);
    void               StartRepaints(int interval_ms, std::function<void()> repaint);
    void               UiTick(cerfcore::CerfEmulator& emu);
    void               RequestShadedCapture();

private:
    const ShaderChainSpec* CopyShaders(const ShaderChainSpec* spec);
    void        PresentGuest(cerfcore::CerfEmulator& emu, cerfcore::FrameSource& source, bool desaturate);
    void        PresentOverlay(cerfcore::CerfEmulator& emu, int visible_w, int visible_h, qreal dpr, bool desaturate);
    static void FitCanvasImage(QImage& image, int w, int h, QImage::Format format);
    static void ForceOpaque(uint32_t* pixels, size_t count);

    std::unique_ptr<QtPresentHooks> hooks_;
    QColor                          background_;
    cerffrontend::ViewportLayout    layout_;
    QImage                          guest_;
    QImage                          dimmed_;
    QImage                          alt_;
    QImage                          overlay_;
    QtFrameGlow                     glow_;
    FrameLayers                     layers_;
    ShaderChainSpec                 shaders_;
    ShaderChainResult               shader_result_;
    ShaderChainResult               reported_shader_;
    std::shared_ptr<ShaderCapture>  capture_;
    QTimer                          repaint_timer_;
};
