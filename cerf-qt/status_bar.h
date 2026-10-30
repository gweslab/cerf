#pragma once

#include "painter.h"
#include "widget_menu_model.h"

#include <cerfcore/core/service.h>

#include <cstddef>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace cerfcore { class HostWidget; }

namespace cerffrontend {

class StatusBar : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static constexpr int      kHeight   = 24;
    static constexpr int      kIconBoxW = 26;
    static constexpr unsigned kTickMs   = 100;

    struct Entry {
        cerfcore::HostWidget* widget = nullptr;
        Rect                  box;
    };

    struct TickResult {
        bool                repaint        = false;
        bool                layout_changed = false;
        std::vector<size_t> tooltips_changed;
    };

    using WidgetFilter = std::function<bool(const cerfcore::HostWidget*)>;

    void       SetFilter(WidgetFilter shown) { filter_ = std::move(shown); }
    bool       Relayout(int width, int height);
    bool       Scroll(int delta);
    bool       SetHover(int x);
    bool       ClearHover();
    TickResult Tick(int width, int height);
    void       Paint(Painter& p, const Rect& client, bool dark);
    void       PaintWidgets(Painter& p, Rgb backdrop);

    std::vector<cerfcore::HostWidget*> ShownWidgets() const;

    const std::vector<Entry>& Entries() const { return layout_; }
    std::string               TooltipAt(size_t index) const;
    cerfcore::HostWidget*     WidgetAt(int x) const;
    bool                      WidgetBox(const cerfcore::HostWidget* w, Rect& out) const;
    bool                      CaptureWidgetBox(Rect& out) const;

    bool PrimaryClick(cerfcore::HostWidget* w);
    bool ContextMenu(cerfcore::HostWidget* w, std::vector<MenuItem>& out);

private:
    struct Glow {
        int  rx         = 0;
        int  tx         = 0;
        bool was_active = false;
    };

    bool SampleActivity(cerfcore::HostWidget* w);
    int  HoverTarget() const;
    bool Hovered(const Rect& box) const;
    void DrawComposited(Painter& p, cerfcore::HostWidget* w, const Rect& box, Rgb bar_bg);

    std::vector<Entry>                                 layout_;
    std::unordered_map<const cerfcore::HostWidget*, Glow> glow_;
    WidgetFilter                                       filter_;
    int                                                scroll_   = 0;
    int                                                width_    = 0;
    int                                                height_   = 0;
    bool                                               hovering_ = false;
    int                                                hover_x_  = 0;
};

}
