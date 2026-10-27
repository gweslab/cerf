#pragma once

#include "painter.h"

#include <cerfcore/core/service.h>
#include <cerfcore/host/notification_stack.h>

#include <cstdint>
#include <string>
#include <vector>

namespace cerffrontend {

class NotificationOverlay : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void Render(Painter& p, int width, int height, int dpi);
    bool HitTest(int x, int y, uint32_t& id) const;

private:
    struct Placed {
        uint32_t                   id   = 0;
        cerfcore::NotificationKind kind = cerfcore::NotificationKind::Warning;
        bool                       more = false;
        Rect                       box;
        Rect                       title_rc;
        Rect                       body_rc;
        std::string                title;
        std::string                body;
    };

    void Relayout(Painter& p, int width, int height, int dpi);
    void Draw(Painter& p);

    std::vector<cerfcore::NotificationCard> cards_;
    std::vector<Placed>                     placed_;
    uint64_t gen_     = ~0ull;
    int      w_       = 0;
    int      h_       = 0;
    int      dpi_     = 0;
    int      radius_  = 0;
    int      shadow_  = 0;
    int      font_px_ = 0;
};

}
