#pragma once

#include "qt_frame_presenter.h"

#include <QImage>
#include <QtGlobal>

#include <atomic>
#include <cstdint>

class QtEmulatorView;

class QtEmulatorPresent final : public QtPresentHooks {
public:
    explicit QtEmulatorPresent(QtEmulatorView& view) : view_(view) {}

    void OnPresentTick(cerfcore::CerfEmulator& emu, bool source_has_frame) override;
    void OnUiTick(cerfcore::CerfEmulator& emu) override;
    bool RenderAlt(cerfcore::CerfEmulator& emu, uint32_t* bits, int w, int h, qreal dpr) override;
    bool   ShouldDesaturate(cerfcore::CerfEmulator& emu) override;
    double GlowReach(cerfcore::CerfEmulator& emu, const cerffrontend::ViewportLayout::Layout& frame) override;
    bool   OverlayShown(cerfcore::CerfEmulator& emu) override;
    const ShaderChainSpec* Shaders(cerfcore::CerfEmulator& emu) override;
    void                   ShadersApplied(cerfcore::CerfEmulator& emu, const ShaderChainResult& result) override;
    void                   ShadedCaptured(cerfcore::CerfEmulator& emu, const ShadedFrame* frame) override;
    void   RenderFrameOverlay(cerfcore::CerfEmulator& emu, QImage& present,
                            const cerffrontend::ViewportLayout::Layout& frame, qreal dpr) override;
    void RenderOverlay(cerfcore::CerfEmulator& emu, QImage& present, int w, int h, qreal dpr) override;

private:
    static int Dpi(qreal dpr);

    QtEmulatorView&   view_;
    std::atomic<bool> source_has_frame_{false};
};
