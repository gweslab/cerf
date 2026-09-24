#include "host_widget_registry.h"

#include "../core/cerf_emulator.h"
#include "../state/state_stream.h"

#include <algorithm>
#include <string>

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
    /* Reversed (Ordered() is ascending by Group): the highest-rank terminal
       widget - the capture lock - leads the block, the rest follow. One
       contiguous block, no inter-widget separators. */
    auto ordered = Ordered();
    for (auto it = ordered.rbegin(); it != ordered.rend(); ++it) {
        HostWidget* w = *it;
        auto items = w->BuildMenu();
        if (items.empty()) {
            /* No menu of its own - a disabled header keeps it discoverable. */
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

void HostWidgetRegistry::SaveState(StateWriter& w) {
    auto ordered = Ordered();
    w.Write<uint32_t>("ordered_count", static_cast<uint32_t>(ordered.size()));
    for (HostWidget* widget : ordered) {
        const std::wstring name = widget->WidgetName();
        w.Write<uint32_t>("name_count", static_cast<uint32_t>(name.size()));
        w.WriteBytes("name", name.data(), name.size() * sizeof(wchar_t));
        w.BeginFrame(0);
        widget->SaveWidgetState(w);
        w.EndFrame();
    }
}

void HostWidgetRegistry::RestoreState(StateReader& r) {
    auto ordered = Ordered();
    uint32_t n = 0;
    r.Read("ordered_count", n);
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t namelen = 0;
        r.Read("name_count", namelen);
        if (namelen > 1024u) r.Reject("widget name of %u characters", namelen);
        std::wstring name(namelen, L'\0');
        r.ReadBytes("name", name.data(), namelen * sizeof(wchar_t));
        if (const uint32_t id = r.EnterFrame(); id != 0u)
            r.Reject("widget '%ls' body in frame 0x%X, this build writes frame 0", name.c_str(), id);
        size_t target = ordered.size();
        for (size_t k = 0; k < ordered.size(); ++k)
            if (ordered[k]->WidgetName() == name) { target = k; break; }
        if (target == ordered.size()) {
            r.SkipFrame();
            continue;
        }
        ordered[target]->RestoreWidgetState(r);
        r.LeaveFrame();
    }
}
