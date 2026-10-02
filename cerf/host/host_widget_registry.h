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

    /* Called from a widget's OnReady - possibly after the UI thread is already
       painting, hence the lock. */
    void Register(HostWidget* w);

    /* Snapshot sorted by (Group, WidgetName). */
    std::vector<HostWidget*> Ordered();

    /* WM_COMMAND id range owned by widget menus, clear of the static
       HostWindow menu enum (100..130, 200..201). */
    static constexpr int kIdBase = 0xC000;
    static constexpr int kIdEnd  = 0xCFFF;
    bool OwnsCommand(int id) const { return id >= kIdBase && id <= kIdEnd; }

    HMENU BuildContextMenu(const std::vector<WidgetMenuItem>& items);

    /* Append a separator + name/submenu per ordered widget (Actions replica). */
    void AppendAllToMenu(HMENU dest);

    /* Run the callback bound to a menu id (no-op if unknown). */
    void Dispatch(int id);

    /* Hibernation: persist each widget's guest-visible state. Widgets register
       lazily (on first Get<>), so the set and order can differ between save and
       restore; each entry is keyed by name and length-framed for lookup + skip. */
    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);

private:
    void ResetIds();
    void AppendItems(HMENU menu, const std::vector<WidgetMenuItem>& items);

    std::mutex                         mtx_;
    std::vector<HostWidget*>           widgets_;
    std::vector<std::function<void()>> id_callbacks_;   /* index = id - kIdBase */
};
