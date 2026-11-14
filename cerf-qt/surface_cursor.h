#pragma once

#include "pointer_overlay.h"

#include <QPointF>
#include <QtGlobal>

class QPainter;

namespace cerfcore {
class CerfEmulator;
enum class PointerKind;
}

namespace cerffrontend {
class ViewportLayout;
}

class SurfaceCursor {
public:
    struct View {
        const cerffrontend::ViewportLayout& layout;
        bool                                cursor_mode;
        bool                                relative_pointer;
        cerfcore::PointerKind               active_kind;
        QPointF                             pointer_at;
        qreal                               dpr;
        double                              guest_scale;
    };

    bool Shown(cerfcore::CerfEmulator& emu, const View& view);
    void Paint(cerfcore::CerfEmulator& emu, QPainter& painter, const View& view);

private:
    PointerOverlay overlay_;
};
