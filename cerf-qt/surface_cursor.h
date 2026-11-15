#pragma once

#include "pointer_overlay.h"

#include <QPointF>

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
        double                              guest_scale;
    };

    CursorPicture Picture(cerfcore::CerfEmulator& emu, const View& view);

private:
    bool Shown(cerfcore::CerfEmulator& emu, const View& view);

    PointerOverlay overlay_;
};
