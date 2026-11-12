#include "host_tap_timing.h"

#include <QGuiApplication>
#include <QStyleHints>

int TapTimeoutMs() { return 0; }

int DoubleTapMinTimeMs() { return 0; }

int DoubleTapTimeoutMs() { return QGuiApplication::styleHints()->mouseDoubleClickInterval(); }

qreal DoubleTapSlopPx(qreal dpr) { return QGuiApplication::styleHints()->touchDoubleTapDistance() * dpr; }
