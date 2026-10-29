#pragma once

#include <wayland-client.h>

#include <cstdint>

class WaylandRegistryScan {
public:
    using GlobalHandler = void (*)(void* data, wl_registry* registry, uint32_t name, const char* interface,
                                   uint32_t version);

    WaylandRegistryScan(wl_display* display, GlobalHandler on_global, void* data);
    ~WaylandRegistryScan();
    WaylandRegistryScan(const WaylandRegistryScan&)            = delete;
    WaylandRegistryScan& operator=(const WaylandRegistryScan&) = delete;

    bool Roundtrip();

private:
    static void OnGlobalRemove(void* data, wl_registry* registry, uint32_t name);

    wl_display*          display_;
    wl_event_queue*      queue_;
    wl_registry*         registry_;
    wl_registry_listener listener_;
};
