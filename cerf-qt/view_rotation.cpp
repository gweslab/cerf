#include "view_rotation.h"

#include "frontend_window.h"
#include "hud_controls.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>
#include <cerfcore/host/frame_renderer.h>

namespace cerffrontend {

REGISTER_SERVICE(ViewRotation);

int ViewRotation::PresentedQuarter() {
    return static_cast<int>((emu_.Get<cerfcore::FrameRenderer>().DisplayQuarter() + static_cast<uint32_t>(quarter_)) & 3u);
}

void ViewRotation::Rotate(int quarters) {
    quarter_ = (quarter_ + quarters) & 3;
    LOG(Lcd, "ViewRotation: %d degrees\n", quarter_ * 90);
    Reapply();
}

void ViewRotation::OnFrameTurned() {
    LOG(Lcd, "ViewRotation: the frame turned, presented at %d degrees\n", PresentedQuarter() * 90);
    Reapply();
}

void ViewRotation::Reapply() {
    emu_.Get<HudControls>().CancelAll();
    emu_.Get<FrontendWindow>().OnPresentationChanged();
}

MenuItem ViewRotation::MenuRow() {
    return MenuItem::Row("Rotate", {MenuItem::IconAction("Rotate left", "rotate_left", [this] { Rotate(-1); }),
                                    MenuItem::IconAction("Rotate right", "rotate_right", [this] { Rotate(1); })});
}

}
