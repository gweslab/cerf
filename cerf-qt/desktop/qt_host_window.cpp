#include "qt_host_window.h"

#include "qt_main_window.h"

#include <QCloseEvent>
#include <QResizeEvent>

void QtHostWindow::ResizeTo(const QSize& size) {
    expected_ = size;
    resize(size);
}

void QtHostWindow::closeEvent(QCloseEvent* event) {
    event->ignore();
    owner_.CloseRequested();
}

void QtHostWindow::changeEvent(QEvent* event) {
    if (event->type() == QEvent::WindowStateChange && isMaximized()) owner_.OnMaximized();
    if (event->type() == QEvent::ActivationChange && !isActiveWindow()) owner_.OnDeactivated();
    QMainWindow::changeEvent(event);
}

void QtHostWindow::resizeEvent(QResizeEvent* event) {
    QMainWindow::resizeEvent(event);
    if (event->spontaneous() && event->size() != expected_ && !isMaximized() && !isFullScreen())
        owner_.OnUserResized();
}
