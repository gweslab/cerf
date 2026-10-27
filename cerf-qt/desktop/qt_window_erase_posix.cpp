#include "qt_window_erase.h"

#include <QCoreApplication>

QtWindowErase::QtWindowErase(QCoreApplication&) {}

bool QtWindowErase::nativeEventFilter(const QByteArray&, void*, qintptr*) { return false; }
