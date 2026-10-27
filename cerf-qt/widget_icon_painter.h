#pragma once

#include "painter.h"

#include <cerfcore/core/service.h>
#include <cerfcore/host/widget_icon.h>

namespace cerffrontend {

class WidgetIconPainter : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void Paint(Painter& p, const Rect& box, const cerfcore::WidgetIcon& icon);

private:
    void Draw(Painter& p, const Rect& box, const cerfcore::ResourceIcon& icon);
    void Draw(Painter& p, const Rect& box, const cerfcore::ChipIcon& icon);
    void Draw(Painter& p, const Rect& box, const cerfcore::HardDiskIcon& icon);
    void Draw(Painter& p, const Rect& box, const cerfcore::LedIcon& icon);
    void Draw(Painter& p, const Rect& box, const cerfcore::LedGridIcon& icon);
    void Draw(Painter& p, const Rect& box, const cerfcore::PowerInputIcon& icon);
    void Draw(Painter& p, const Rect& box, const cerfcore::BatteryIcon& icon);
    void Draw(Painter& p, const Rect& box, const cerfcore::FolderIcon& icon);
};

}
