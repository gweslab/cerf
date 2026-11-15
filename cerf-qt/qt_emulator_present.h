#pragma once

#include "qt_frame_presenter.h"

#include <atomic>

class QtEmulatorView;

class QtEmulatorPresent final : public QtPresentHooks {
public:
    explicit QtEmulatorPresent(QtEmulatorView& view) : view_(view) {}

    void OnPresentTick(cerfcore::CerfEmulator& emu) override;
    void OnUiTick(cerfcore::CerfEmulator& emu) override;
    bool ShowsGuest(cerfcore::CerfEmulator& emu) override;
    bool   FreezeFrame(cerfcore::CerfEmulator& emu) override;
    double GlowReach(cerfcore::CerfEmulator& emu, const cerffrontend::ViewportLayout::Layout& frame) override;
    const ShaderChainSpec* Shaders(cerfcore::CerfEmulator& emu) override;
    void                   ShadersApplied(cerfcore::CerfEmulator& emu, const ShaderChainResult& result) override;
    void                   ShadedCaptured(cerfcore::CerfEmulator& emu, const ShadedFrame* frame) override;

private:
    QtEmulatorView&   view_;
    std::atomic<bool> content_latched_{false};
};
