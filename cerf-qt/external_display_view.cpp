#include "external_display_view.h"

#include "external_display_sources.h"
#include "qt_device_pixels.h"

#include "present_timing.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QQuickWindow>

#include <algorithm>

ExternalDisplayView::ExternalDisplayView(QQuickItem* parent) : FrameViewItem(parent) {}

ExternalDisplayView::~ExternalDisplayView() { Detach(); }

void ExternalDisplayView::Attach(int source_id, cerfcore::CerfEmulator& emu, uint32_t surf_w, uint32_t surf_h) {
    gate_.Attach(emu);
    source_id_ = source_id;
    presenter_ = std::make_unique<QtFramePresenter>(std::make_unique<QtPresentHooks>(), surf_w, surf_h, FillColor());
    presenter_->Layout().SetMode(cerffrontend::ViewportMode::Aspect);
    presenter_->StartRepaints(cerffrontend::kDefaultPresentIntervalMs, [this] { update(); });
    emit surfaceSizeChanged();
}

void ExternalDisplayView::Detach() {
    presenter_.reset();
    gate_ = cerfcore::InstanceGate();
}

void ExternalDisplayView::SetSurfaceSize(uint32_t w, uint32_t h) {
    if (presenter_ && presenter_->SetGuestSurfaceSize(w, h)) emit surfaceSizeChanged();
}

bool ExternalDisplayView::Capture(std::vector<uint32_t>& out, uint32_t& w, uint32_t& h) {
    bool captured = false;
    gate_.Run([&](cerfcore::CerfEmulator& emu) {
        emu.Get<ExternalDisplaySources>().UseSource(source_id_, [&](cerfcore::FrameSource& source) {
            captured = presenter_->Capture(source, out, w, h);
        });
    });
    return captured;
}

int ExternalDisplayView::SurfaceWidth() const {
    return presenter_ ? static_cast<int>(presenter_->Layout().SurfaceWidth()) : 0;
}

int ExternalDisplayView::SurfaceHeight() const {
    return presenter_ ? static_cast<int>(presenter_->Layout().SurfaceHeight()) : 0;
}

const FrameLayers* ExternalDisplayView::PresentLayers() {
    if (!presenter_) return nullptr;
    const FrameLayers* layers = nullptr;
    gate_.Run([this, &layers](cerfcore::CerfEmulator& emu) {
        const qreal dpr    = window()->devicePixelRatio();
        const QSize canvas = DeviceCanvasSize(width(), height(), PixelScale());
        presenter_->SetCanvasSize(canvas.width(), canvas.height());
        emu.Get<ExternalDisplaySources>().UseSource(source_id_, [&](cerfcore::FrameSource& source) {
            layers = &presenter_->Present(emu, source, canvas.width(), canvas.height(), dpr);
        });
    });
    return layers;
}
