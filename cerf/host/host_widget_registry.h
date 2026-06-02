#pragma once

#define NOMINMAX
#include <windows.h>

#include "../core/service.h"
#include "host_widget.h"

#include <functional>
#include <mutex>
#include <vector>

class HostWidgetRegistry : public Service {
public:
    using Service::Service;

    /* Called from a widget's OnReady — possibly after the UI thread is already
       painting, hence the lock. */
    void Register(HostWidget* w);

    /* Snapshot sorted by (Group, WidgetName). */
    std::vector<HostWidget*> Ordered();

    /* WM_COMMAND id range owned by widget menus, clear of the static
       HostWindow menu enum (100..130, 200..201). */
    static constexpr int kIdBase = 0xC000;
    static constexpr int kIdEnd  = 0xCFFF;
    bool OwnsCommand(int id) const { return id >= kIdBase && id <= kIdEnd; }

    /* Fresh popup from w->BuildMenu(); caller DestroyMenu()s it. */
    HMENU BuildContextMenu(HostWidget* w);

    /* Append a separator + name/submenu per ordered widget (Actions replica). */
    void AppendAllToMenu(HMENU dest);

    /* Run the callback bound to a menu id (no-op if unknown). */
    void Dispatch(int id);

private:
    void ResetIds();
    void AppendItems(HMENU menu, const std::vector<WidgetMenuItem>& items);

    std::mutex                         mtx_;
    std::vector<HostWidget*>           widgets_;
    std::vector<std::function<void()>> id_callbacks_;   /* index = id - kIdBase */
};
