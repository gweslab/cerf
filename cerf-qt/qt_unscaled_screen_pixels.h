#pragma once

#include <QSize>

class QScreen;

QSize UnscaledScreenPixels(const QScreen& screen);
QSize UnscaledWorkAreaPixels(const QScreen& screen);
