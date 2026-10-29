#include "external_display_view.h"

#include "../external_display_sources.h"
#include "../qt_device_pixels.h"

#include "../present_timing.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QPainter>
#include <QQuickWindow>

#include <algorithm>

ExternalDisplayView::ExternalDisplayView(QQuickItem* parent) : QQuickPaintedItem(parent) {
    setOpaquePainting(true);
}

ExternalDisplayView::~ExternalDisplayView() { Detach(); }

void ExternalDisplayView::Attach(int source_id, cerfcore::CerfEmulator& emu, uint32_t surf_w, uint32_t surf_h) {
    gate_.Attach(emu);
    source_id_ = source_id;
    presenter_ = std::make_unique<QtFramePresenter>(std::make_unique<QtPresentHooks>(), surf_w, surf_h, fillColor());
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

int ExternalDisplayView::SurfaceWidth() const {
    return presenter_ ? static_cast<int>(presenter_->Layout().SurfaceWidth()) : 0;
}

int ExternalDisplayView::SurfaceHeight() const {
    return presenter_ ? static_cast<int>(presenter_->Layout().SurfaceHeight()) : 0;
}

void ExternalDisplayView::paint(QPainter* painter) {
    if (!presenter_) return;
    gate_.Run([this, painter](cerfcore::CerfEmulator& emu) {
        const qreal dpr    = window()->devicePixelRatio();
        const QSize canvas = DeviceCanvasSize(width(), height(), dpr);
        presenter_->SetCanvasSize(canvas.width(), canvas.height());
        presenter_->DrawTo(emu, emu.Get<ExternalDisplaySources>().Source(source_id_), *painter, canvas.width(),
                           canvas.height(), dpr);
    });
}
