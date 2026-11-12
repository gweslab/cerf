#pragma once

#include "hud_screen_layout.h"
#include "view_placement.h"

#include <cerfcore/core/service.h>

#include <QMarginsF>
#include <QSizeF>

namespace cerffrontend {
class ViewportLayout;
}

class SurfaceAreaPlanner : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    ViewArea                       AreaFor(QSizeF logical, const QMarginsF& safe, qreal dpr,
                                           const cerffrontend::ViewportLayout& layout);
    cerffrontend::HudScreenMetrics HudMetrics(qreal dpr);
};
