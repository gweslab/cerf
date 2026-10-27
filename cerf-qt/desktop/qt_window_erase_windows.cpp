#include "qt_window_erase.h"

#include <QCoreApplication>
#include <QGuiApplication>
#include <QQuickWindow>

#define NOMINMAX
#include <windows.h>

QtWindowErase::QtWindowErase(QCoreApplication& app) { app.installNativeEventFilter(this); }

bool QtWindowErase::nativeEventFilter(const QByteArray& type, void* message, qintptr* result) {
    const auto* msg = static_cast<const MSG*>(message);
    if (type != "windows_generic_MSG" || msg->message != WM_ERASEBKGND) return false;
    for (QWindow* window : QGuiApplication::allWindows()) {
        auto* quick = qobject_cast<QQuickWindow*>(window);
        if (!quick || !quick->handle() || reinterpret_cast<HWND>(quick->winId()) != msg->hwnd) continue;
        const QColor color = quick->color();
        RECT         client;
        GetClientRect(msg->hwnd, &client);
        HBRUSH brush = CreateSolidBrush(RGB(color.red(), color.green(), color.blue()));
        FillRect(reinterpret_cast<HDC>(msg->wParam), &client, brush);
        DeleteObject(brush);
        *result = 1;
        return true;
    }
    return false;
}
