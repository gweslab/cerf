#include "host_widget_registry.h"

#include "../core/cerf_emulator.h"

#include <algorithm>

REGISTER_SERVICE(HostWidgetRegistry);

void HostWidgetRegistry::Register(HostWidget* w) {
    std::lock_guard<std::mutex> lk(mtx_);
    widgets_.push_back(w);
}

std::vector<HostWidget*> HostWidgetRegistry::Ordered() {
    std::vector<HostWidget*> v;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        v = widgets_;
    }
    std::stable_sort(v.begin(), v.end(), [](HostWidget* a, HostWidget* b) {
        const int ga = static_cast<int>(a->Group());
        const int gb = static_cast<int>(b->Group());
        if (ga != gb) return ga < gb;
        return a->WidgetName() < b->WidgetName();
    });
    return v;
}

void HostWidgetRegistry::ResetIds() {
    id_callbacks_.clear();
}

void HostWidgetRegistry::AppendItems(HMENU menu,
                                     const std::vector<WidgetMenuItem>& items) {
    for (const auto& it : items) {
        if (it.label.empty()) {
            AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            continue;
        }
        if (!it.submenu.empty()) {
            HMENU sub = CreatePopupMenu();
            AppendItems(sub, it.submenu);
            AppendMenuW(menu, MF_POPUP | (it.enabled ? 0u : MF_GRAYED),
                        reinterpret_cast<UINT_PTR>(sub), it.label.c_str());
            continue;
        }
        UINT flags = MF_STRING;
        if (!it.enabled || !it.on_click) flags |= MF_GRAYED;
        if (it.checked)                  flags |= MF_CHECKED;
        UINT id = 0;
        if (it.on_click && it.enabled) {
            id = static_cast<UINT>(kIdBase + id_callbacks_.size());
            id_callbacks_.push_back(it.on_click);
        }
        AppendMenuW(menu, flags, id, it.label.c_str());
    }
}

HMENU HostWidgetRegistry::BuildContextMenu(HostWidget* w) {
    ResetIds();
    HMENU m = CreatePopupMenu();
    AppendItems(m, w->BuildMenu());
    return m;
}

void HostWidgetRegistry::AppendAllToMenu(HMENU dest) {
    ResetIds();
    /* Reversed (Ordered() is ascending by Group): the terminal InputControl
       group — the capture lock — leads the block, the device widgets follow.
       One contiguous block, no inter-widget separators. */
    auto ordered = Ordered();
    for (auto it = ordered.rbegin(); it != ordered.rend(); ++it) {
        HostWidget* w = *it;
        auto items = w->BuildMenu();
        if (items.empty()) {
            /* No menu of its own — a disabled header keeps it discoverable. */
            AppendMenuW(dest, MF_STRING | MF_GRAYED, 0, w->WidgetName().c_str());
        } else if (items.size() == 1 && items[0].submenu.empty()) {
            AppendItems(dest, items);
        } else {
            HMENU sub = CreatePopupMenu();
            AppendItems(sub, items);
            AppendMenuW(dest, MF_POPUP, reinterpret_cast<UINT_PTR>(sub),
                        w->WidgetName().c_str());
        }
    }
}

void HostWidgetRegistry::Dispatch(int id) {
    const size_t idx = static_cast<size_t>(id - kIdBase);
    std::function<void()> cb;
    if (idx < id_callbacks_.size()) cb = id_callbacks_[idx];
    if (cb) cb();
}
