#include "qt_host_window.h"

#include "qt_main_window.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QCloseEvent>
#include <QResizeEvent>

void QtHostWindow::ResizeTo(const QSize& size) {
    expected_ = size;
    resize(size);
}

void QtHostWindow::closeEvent(QCloseEvent* event) {
    event->ignore();
    gate_.Run([](cerfcore::CerfEmulator& emu) { emu.Get<QtMainWindow>().CloseRequested(); });
}

void QtHostWindow::changeEvent(QEvent* event) {
    if (event->type() == QEvent::WindowStateChange && isMaximized())
        gate_.Run([](cerfcore::CerfEmulator& emu) { emu.Get<QtMainWindow>().OnMaximized(); });
    if (event->type() == QEvent::ActivationChange && !isActiveWindow())
        gate_.Run([](cerfcore::CerfEmulator& emu) { emu.Get<QtMainWindow>().OnDeactivated(); });
    QMainWindow::changeEvent(event);
}

void QtHostWindow::resizeEvent(QResizeEvent* event) {
    QMainWindow::resizeEvent(event);
    if (event->spontaneous() && event->size() != expected_ && !isMaximized() && !isFullScreen())
        gate_.Run([](cerfcore::CerfEmulator& emu) { emu.Get<QtMainWindow>().OnUserResized(); });
}
