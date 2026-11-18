#include "surface_overlays.h"

#include "canvas_tabs.h"
#include "hud_nodes.h"
#include "qt_paint_resources.h"
#include "viewport_layout.h"

#include <cerfcore/core/cerf_emulator.h>

#include <utility>

SurfaceOverlays::SurfaceOverlays(QObject* parent)
    : QObject(parent),
      hud_(cerffrontend::HudNodes::Roles(), this),
      cards_(cerffrontend::NotificationOverlay::Roles(), this) {}

void SurfaceOverlays::PlaceCards(const QVariantList& placed) {
    placed_.clear();
    for (const QVariant& entry : placed) {
        const QVariantMap card = entry.toMap();
        placed_.push_back({card.value(QStringLiteral("cardId")).toUInt(),
                           QRectF(card.value(QStringLiteral("x")).toDouble(), card.value(QStringLiteral("y")).toDouble(),
                                  card.value(QStringLiteral("width")).toDouble(),
                                  card.value(QStringLiteral("height")).toDouble())});
    }
}

void SurfaceOverlays::ShowFonts(cerfcore::CerfEmulator& emu) {
    const auto& resources = emu.Get<QtPaintResources>();
    ui_family_            = resources.UiFamily();
    mono_family_          = resources.MonoFamily();
    emit fontsChanged();
}

void SurfaceOverlays::ShowCanvas(const cerffrontend::ViewportLayout& layout, QPointF scale) {
    if (scale != scale_) {
        scale_ = scale;
        emit pixelScaleChanged();
    }
    const QRectF canvas(0, 0, layout.CanvasWidth() / scale.x(), layout.CanvasHeight() / scale.y());
    if (canvas != canvas_) {
        canvas_ = canvas;
        emit canvasChanged();
    }
}

void SurfaceOverlays::ShowCards(cerfcore::CerfEmulator& emu, QPointF scale) {
    auto& notifications = emu.Get<cerffrontend::NotificationOverlay>();
    cards_.Update(notifications.Cards());
    notifications.SetPlaced(placed_, scale);
}

void SurfaceOverlays::Refresh(cerfcore::CerfEmulator& emu, const cerffrontend::ViewportLayout& layout, QPointF scale,
                              CursorPicture cursor) {
    ShowCanvas(layout, scale);
    auto&      tabs        = emu.Get<cerffrontend::CanvasTabs>();
    const bool framebuffer = tabs.Current() == cerfcore::CanvasTab::Framebuffer;
    hud_.Update(framebuffer ? emu.Get<cerffrontend::HudNodes>().Build(layout.Compute(), scale) : QList<QVariantMap>());
    ShowCards(emu, scale);
    const bool dimmed = tabs.ShouldDesaturate();
    if (dimmed != dimmed_) {
        dimmed_ = dimmed;
        emit dimmedChanged();
    }
    const QPointF arrow_at = cursor.arrow ? QPointF(cursor.hot.x() / scale.x(), cursor.hot.y() / scale.y()) : QPointF();
    if (cursor.arrow != arrow_shown_ || arrow_at != arrow_at_) {
        arrow_shown_ = cursor.arrow;
        arrow_at_    = arrow_at;
        emit arrowChanged();
    }
    cursor_ = std::move(cursor);
    emit cursorChanged();
}
