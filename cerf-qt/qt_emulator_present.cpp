#include "qt_emulator_present.h"

#include "qt_emulator_view.h"

#include "canvas_input.h"
#include "canvas_tabs.h"
#include "guest_content_latch.h"
#include "hud_selection.h"
#include "screenshots.h"
#include "shader_selection.h"

#include <cerfcore/core/cerf_emulator.h>

void QtEmulatorPresent::OnPresentTick(cerfcore::CerfEmulator& emu) {
    content_latched_.store(emu.Get<cerffrontend::GuestContentLatch>().Probe(), std::memory_order_release);
}

void QtEmulatorPresent::OnUiTick(cerfcore::CerfEmulator& emu) {
    if (emu.Get<cerffrontend::CanvasTabs>().OnPresentTick(content_latched_.load(std::memory_order_acquire)))
        view_.SetFramebufferActive(true);
    emu.Get<cerffrontend::CanvasInput>().RefreshLock();
}

bool QtEmulatorPresent::ShowsGuest(cerfcore::CerfEmulator& emu) {
    return emu.Get<cerffrontend::CanvasTabs>().Current() == cerfcore::CanvasTab::Framebuffer;
}

bool QtEmulatorPresent::FreezeFrame(cerfcore::CerfEmulator& emu) {
    return emu.Get<cerffrontend::CanvasTabs>().ShouldDesaturate();
}

double QtEmulatorPresent::GlowReach(cerfcore::CerfEmulator& emu, const cerffrontend::ViewportLayout::Layout& frame) {
    return emu.Get<cerffrontend::HudSelection>().PanelReach(frame);
}

const ShaderChainSpec* QtEmulatorPresent::Shaders(cerfcore::CerfEmulator& emu) {
    return &emu.Get<cerffrontend::ShaderSelection>().Spec();
}

void QtEmulatorPresent::ShadersApplied(cerfcore::CerfEmulator& emu, const ShaderChainResult& result) {
    emu.Get<cerffrontend::ShaderSelection>().Report(result);
}

void QtEmulatorPresent::ShadedCaptured(cerfcore::CerfEmulator& emu, const ShadedFrame* frame) {
    emu.Get<cerffrontend::Screenshots>().ShadedCaptured(frame);
}
