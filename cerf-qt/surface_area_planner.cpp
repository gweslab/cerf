#include "surface_area_planner.h"

#include "hud_selection.h"
#include "qt_emulator_window.h"
#include "qt_device_pixels.h"
#include "viewport_layout.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>

#include <cmath>

REGISTER_SERVICE(SurfaceAreaPlanner);

cerffrontend::HudScreenMetrics SurfaceAreaPlanner::HudMetrics(qreal dpr) {
    if (!emu_.Get<QtEmulatorWindow>().AdoptsHostResolution()) return {dpr, std::nullopt};
    const auto live = emu_.Get<cerfcore::DeviceConfig>().Live();
    return {dpr, cerfcore::DbLcdPanelSize{live->board_configurable_screen_width, live->board_configurable_screen_height}};
}

ViewArea SurfaceAreaPlanner::BaseArea(QSizeF logical, const QMarginsF& safe, QPointF scale) {
    const QSize canvas = DeviceCanvasSize(logical.width(), logical.height(), scale);
    return ViewArea{canvas.width(),
                    canvas.height(),
                    DeviceExtent(safe.left(), scale.x()),
                    DeviceExtent(safe.top(), scale.y()),
                    DeviceExtent(safe.right(), scale.x()),
                    DeviceExtent(safe.bottom(), scale.y())};
}

ViewArea SurfaceAreaPlanner::AreaFor(QSizeF logical, const QMarginsF& safe, QPointF scale, qreal dpr,
                                     const cerffrontend::ViewportLayout& layout) {
    ViewArea                      a   = BaseArea(logical, safe, scale);
    const cerffrontend::HudInsets hud = emu_.Get<cerffrontend::HudSelection>().InsideInsets(
        a.width - a.left - a.right, a.height - a.top - a.bottom, layout.Presentation().quarter, layout.SurfaceWidth(),
        layout.SurfaceHeight(), HudMetrics(dpr));
    const auto edge = [](int inset, double depth) { return depth > 0.0 ? inset + static_cast<int>(std::ceil(depth)) : 0; };
    a.hud_left   = edge(a.left, hud.left);
    a.hud_top    = edge(a.top, hud.top);
    a.hud_right  = edge(a.right, hud.right);
    a.hud_bottom = edge(a.bottom, hud.bottom);
    return a;
}
