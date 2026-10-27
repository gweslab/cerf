#include "external_display_view.h"

#include "../qt_device_pixels.h"

#include "../present_timing.h"

#include <QPainter>
#include <QQuickWindow>

#include <algorithm>

ExternalDisplayView::ExternalDisplayView(QQuickItem* parent) : QQuickPaintedItem(parent) {
    setOpaquePainting(true);
}

ExternalDisplayView::~ExternalDisplayView() { Detach(); }

void ExternalDisplayView::Attach(cerfcore::FrameSource& source, uint32_t surf_w, uint32_t surf_h) {
    presenter_ = std::make_unique<QtFramePresenter>(source, std::make_unique<QtPresentHooks>(), surf_w, surf_h,
                                                    fillColor());
    presenter_->Layout().SetMode(cerffrontend::ViewportMode::Aspect);
    presenter_->StartRepaints(cerffrontend::kDefaultPresentIntervalMs, [this] { update(); });
    emit surfaceSizeChanged();
}

void ExternalDisplayView::Detach() { presenter_.reset(); }

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
    const qreal dpr    = window()->devicePixelRatio();
    const QSize canvas = DeviceCanvasSize(width(), height(), dpr);
    presenter_->SetCanvasSize(canvas.width(), canvas.height());
    presenter_->DrawTo(*painter, canvas.width(), canvas.height(), dpr);
}
