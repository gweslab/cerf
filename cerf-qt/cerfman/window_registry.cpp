#include "window_registry.h"

#include "../bring_window_to_front.h"

#include <cerfcore/core/cerf_emulator.h>

REGISTER_SERVICE(WindowRegistry);

QWindow* WindowRegistry::Raise(const QString& key) {
    QWindow* window = windows_.value(key);
    if (window == nullptr || !window->isVisible()) return nullptr;
    BringWindowToFront(*window);
    return window;
}

void WindowRegistry::Track(const QString& key, QWindow* window) { windows_.insert(key, window); }
