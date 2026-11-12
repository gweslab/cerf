#include "native_menu_bar.h"

#include <QGuiApplication>

bool NativeMenuBar::Active() { return !QGuiApplication::testAttribute(Qt::AA_DontUseNativeMenuBar); }
