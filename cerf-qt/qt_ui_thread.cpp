#include "qt_ui_thread.h"

#include <QCoreApplication>
#include <QThread>

bool OnUiThread() { return QThread::currentThread() == QCoreApplication::instance()->thread(); }
