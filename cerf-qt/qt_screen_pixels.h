#pragma once

#include <QSize>

class QScreen;

inline constexpr QSize kNoScreenPixels{0, 0};

QSize ScreenPixels(const QScreen& screen);
#ifdef Q_OS_ANDROID
QSize ScreenSafeZonePixels(const QScreen& screen);
#else
QSize ScreenWorkAreaPixels(const QScreen& screen);
#endif
