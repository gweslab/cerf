#include "safe_zone_metrics.h"

#include "../qt_screen_pixels.h"

#include <QQuickWindow>
#include <QScreen>

QSize SafeZoneMetrics::SafeZonePixels(QQuickItem* item) const { return ScreenSafeZonePixels(*item->window()->screen()); }
