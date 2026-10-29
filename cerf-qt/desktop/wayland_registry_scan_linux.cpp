#include "wayland_registry_scan.h"

WaylandRegistryScan::WaylandRegistryScan(wl_display* display, GlobalHandler on_global, void* data)
    : display_(display), queue_(wl_display_create_queue(display)), listener_{on_global, &OnGlobalRemove} {
    auto* wrapper = static_cast<wl_display*>(wl_proxy_create_wrapper(display));
    wl_proxy_set_queue(reinterpret_cast<wl_proxy*>(wrapper), queue_);
    registry_ = wl_display_get_registry(wrapper);
    wl_proxy_wrapper_destroy(wrapper);
    wl_registry_add_listener(registry_, &listener_, data);
}

WaylandRegistryScan::~WaylandRegistryScan() {
    wl_registry_destroy(registry_);
    wl_event_queue_destroy(queue_);
}

bool WaylandRegistryScan::Roundtrip() { return wl_display_roundtrip_queue(display_, queue_) >= 0; }

void WaylandRegistryScan::OnGlobalRemove(void*, wl_registry*, uint32_t) {}
