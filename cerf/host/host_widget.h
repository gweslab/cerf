#pragma once

#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <functional>
#include <string>
#include <vector>

class StateWriter;
class StateReader;

/* HostWidget is Service-free: implementers already derive Service (a
   peripheral via Peripheral), so a Service base here would make emu_
   ambiguous in them. Implementers self-register with HostWidgetRegistry
   from OnReady. */

enum class WidgetGroup : int {
    Storage   = 0,
    Network,
    Pcmcia,
    Usb,
    Indicator,
    Power,
    Debug,
    /* Terminal range - pinned to the right of the bar (always shown) and to the
       top of the Actions menu. The capture lock takes the highest rank so it is
       always the very last; other input widgets sort ahead of it. */
    GuestAdditions = 900,  /* always third from the right / third in Actions */
    InputControl   = 1000, /* input-device widgets, e.g. the touch/pointer switch */
    InputCapture   = 1100, /* the capture lock - always rightmost / menu-top */
};

struct WidgetMenuItem {
    std::wstring                label;          /* empty => separator */
    bool                        enabled = true;
    bool                        checked = false;
    std::function<void()>       on_click;       /* null + empty submenu => static label */
    std::vector<WidgetMenuItem> submenu;
};

/* One top-level entry in a widget's menu, owning its own items and dirty-poll
   - a sub-widget without an icon. */
class HostMenuSection {
public:
    virtual ~HostMenuSection() = default;
    virtual std::wstring Label() const = 0;
    virtual std::vector<WidgetMenuItem> BuildItems() { return {}; }
    virtual bool PollDirty() { return false; }
    virtual void SaveState(StateWriter&) const {}
    virtual void RestoreState(StateReader&) {}
};

class HostWidget {
public:
    virtual ~HostWidget() = default;

    virtual std::wstring WidgetName() const = 0;     /* sort key + default tooltip */
    virtual WidgetGroup  Group() const = 0;
    virtual std::wstring Tooltip() const { return WidgetName(); }

    virtual void OnPrimaryAction() {}                /* left-click */
    virtual std::vector<WidgetMenuItem> BuildMenu() { return {}; }  /* right-click + menu replica */
    virtual bool PrimaryActionOpensMenu() const { return false; }

    /* false => the icon is dimmed to read as a disabled peripheral. */
    virtual bool IsEnabled() const { return true; }

    /* Custom GDI icon drawn into box. (An HICON/.ico path arrives with the
       resource infrastructure in a later phase; today every widget draws.) */
    virtual void DrawIcon(HDC dc, const RECT& box) const = 0;

    static void DrawChipIcon(HDC dc, const RECT& box);

    /* Hot-path safe: an implementer marks data activity from its read/write
       path. One relaxed atomic store, no lock. */
    void MarkRx() { rx_pending_.store(true, std::memory_order_relaxed); }
    void MarkTx() { tx_pending_.store(true, std::memory_order_relaxed); }

    /* Returns true while a repaint is still needed - including the tick after
       going idle, else the activity dot is never cleared. UI-thread only. */
    bool SampleActivity();
    void DrawComposited(HDC dc, const RECT& box, COLORREF bar_bg);

    /* Per-tick repaint check for indicators that change without RX/TX (e.g. an
       LED). Return true when the drawn appearance changed. UI-thread only. */
    virtual bool PollDirty() { return false; }

    virtual void SaveWidgetState(StateWriter&) const {}
    virtual void RestoreWidgetState(StateReader&) {}

private:
    std::atomic<bool> rx_pending_{false};
    std::atomic<bool> tx_pending_{false};
    int  rx_glow_     = 0;
    int  tx_glow_     = 0;
    bool was_active_  = false;
};
