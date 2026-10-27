#include "qt_screen_pixels.h"

#include "qt_unscaled_screen_pixels.h"

QSize ScreenPixels(const QScreen& screen) { return UnscaledScreenPixels(screen); }

QSize ScreenWorkAreaPixels(const QScreen& screen) { return UnscaledWorkAreaPixels(screen); }
