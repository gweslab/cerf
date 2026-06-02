#pragma once

#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <functional>
#include <string>
#include <vector>

/* DO NOT make HostWidget derive Service — implementers already derive Service
   (a peripheral via Peripheral), and a second Service base makes emu_ ambiguous
   in them. Implementers self-register with HostWidgetRegistry from OnReady. */

enum class WidgetGroup : int {
    Storage   = 0,
    Network,
    Pcmcia,
    Indicator,
    Power,
    Debug,
    /* Terminal group — always sorts last (rightmost in the bar). Reserved for
       UI-owned widgets such as the input-capture lock. */
    InputControl = 1000,
};

struct WidgetMenuItem {
    std::wstring                label;          /* empty => separator */
    bool                        enabled = true;
    bool                        checked = false;
    std::function<void()>       on_click;       /* null + empty submenu => static label */
    std::vector<WidgetMenuItem> submenu;
};

class HostWidget {
public:
    virtual ~HostWidget() = default;

    virtual std::wstring WidgetName() const = 0;     /* sort key + default tooltip */
    virtual WidgetGroup  Group() const = 0;
    virtual std::wstring Tooltip() const { return WidgetName(); }

    virtual void OnPrimaryAction() {}                /* left-click */
    virtual std::vector<WidgetMenuItem> BuildMenu() { return {}; }  /* right-click + menu replica */

    /* false => the icon is dimmed to read as a disabled peripheral. */
    virtual bool IsEnabled() const { return true; }

    /* Custom GDI icon drawn into box. (An HICON/.ico path arrives with the
       resource infrastructure in a later phase; today every widget draws.) */
    virtual void DrawIcon(HDC dc, const RECT& box) const = 0;

    /* Hot-path safe: an implementer marks data activity from its read/write
       path. One relaxed atomic store, no lock. */
    void MarkRx() { rx_pending_.store(true, std::memory_order_relaxed); }
    void MarkTx() { tx_pending_.store(true, std::memory_order_relaxed); }

    /* Returns true while a repaint is still needed — including the tick after
       going idle, else the activity dot is never cleared. UI-thread only. */
    bool SampleActivity();
    void DrawComposited(HDC dc, const RECT& box);

    /* Per-tick repaint check for indicators that change without RX/TX (e.g. an
       LED). Return true when the drawn appearance changed. UI-thread only. */
    virtual bool PollDirty() { return false; }

private:
    std::atomic<bool> rx_pending_{false};
    std::atomic<bool> tx_pending_{false};
    int  rx_glow_     = 0;
    int  tx_glow_     = 0;
    bool was_active_  = false;
};
