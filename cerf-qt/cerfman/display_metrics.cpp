#include "display_metrics.h"

#include "../qt_screen_pixels.h"

#include <QQuickWindow>
#include <QScreen>

QSize DisplayMetrics::ScreenPixels(QQuickItem* item) const { return ::ScreenPixels(*item->window()->screen()); }
