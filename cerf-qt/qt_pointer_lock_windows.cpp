#include "qt_pointer_lock.h"

#include <cerfcore/core/log.h>

#include <QAbstractNativeEventFilter>
#include <QByteArray>
#include <QCoreApplication>
#include <QWindow>

#define NOMINMAX
#include <windows.h>

#include <hidusage.h>

#include <climits>
#include <cmath>

namespace {

class RawMousePointerLock final : public QtPointerLock, public QAbstractNativeEventFilter {
public:
    explicit RawMousePointerLock(QtRelativeMotionSink& sink) : sink_(sink) {}
    ~RawMousePointerLock() override;

    bool Lock(QWindow& window) override;
    void Unlock() override;
    bool CanWarp() override { return true; }

    bool nativeEventFilter(const QByteArray& type, void* message, qintptr* result) override;

private:
    POINT RestOnScreen() const;
    void  Confine();
    void  OnRawMouse(const RAWMOUSE& mouse);

    QtRelativeMotionSink& sink_;
    QWindow*              window_          = nullptr;
    HWND                  hwnd_            = nullptr;
    bool                  absolute_known_  = false;
    LONG                  absolute_last_x_ = 0;
    LONG                  absolute_last_y_ = 0;
};

RawMousePointerLock::~RawMousePointerLock() {
    if (window_ != nullptr) Unlock();
}

bool RawMousePointerLock::Lock(QWindow& window) {
    const HWND           hwnd = reinterpret_cast<HWND>(window.winId());
    const RAWINPUTDEVICE device{HID_USAGE_PAGE_GENERIC, HID_USAGE_GENERIC_MOUSE, 0, hwnd};
    if (!RegisterRawInputDevices(&device, 1, sizeof(device))) {
        LOG(Caution, "PointerLock: RegisterRawInputDevices failed (%lu)\n", GetLastError());
        return false;
    }
    window_         = &window;
    hwnd_           = hwnd;
    absolute_known_ = false;
    QCoreApplication::instance()->installNativeEventFilter(this);
    Confine();
    const POINT at = RestOnScreen();
    SetCursorPos(at.x, at.y);
    return true;
}

void RawMousePointerLock::Unlock() {
    QCoreApplication::instance()->removeNativeEventFilter(this);
    const RAWINPUTDEVICE device{HID_USAGE_PAGE_GENERIC, HID_USAGE_GENERIC_MOUSE, RIDEV_REMOVE, nullptr};
    if (!RegisterRawInputDevices(&device, 1, sizeof(device)))
        LOG(Caution, "PointerLock: removing the raw mouse registration failed (%lu)\n", GetLastError());
    ClipCursor(nullptr);
    window_ = nullptr;
    hwnd_   = nullptr;
}

POINT RawMousePointerLock::RestOnScreen() const {
    const QPointF rest = sink_.RestInWindow();
    const qreal   dpr  = window_->devicePixelRatio();
    POINT         at{std::lround(rest.x() * dpr), std::lround(rest.y() * dpr)};
    ClientToScreen(hwnd_, &at);
    return at;
}

void RawMousePointerLock::Confine() {
    const POINT at = RestOnScreen();
    const RECT  want{at.x, at.y, at.x + 1, at.y + 1};
    RECT        now{};
    if (GetClipCursor(&now) && EqualRect(&now, &want)) return;
    ClipCursor(&want);
}

bool RawMousePointerLock::nativeEventFilter(const QByteArray& type, void* message, qintptr*) {
    if (type != "windows_generic_MSG") return false;
    const MSG* msg = static_cast<const MSG*>(message);
    if (msg->message != WM_INPUT || msg->hwnd != hwnd_) return false;
    RAWINPUT input{};
    UINT     size = sizeof(input);
    if (GetRawInputData(reinterpret_cast<HRAWINPUT>(msg->lParam), RID_INPUT, &input, &size, sizeof(RAWINPUTHEADER)) ==
        static_cast<UINT>(-1)) {
        LOG(Caution, "PointerLock: GetRawInputData failed (%lu)\n", GetLastError());
        return false;
    }
    if (input.header.dwType == RIM_TYPEMOUSE) OnRawMouse(input.data.mouse);
    return false;
}

void RawMousePointerLock::OnRawMouse(const RAWMOUSE& mouse) {
    Confine();
    LONG dx = mouse.lLastX;
    LONG dy = mouse.lLastY;
    if (mouse.usFlags & MOUSE_MOVE_ABSOLUTE) {
        const bool virtual_desktop = (mouse.usFlags & MOUSE_VIRTUAL_DESKTOP) != 0;
        const int  left            = virtual_desktop ? GetSystemMetrics(SM_XVIRTUALSCREEN) : 0;
        const int  top             = virtual_desktop ? GetSystemMetrics(SM_YVIRTUALSCREEN) : 0;
        const int  width           = GetSystemMetrics(virtual_desktop ? SM_CXVIRTUALSCREEN : SM_CXSCREEN);
        const int  height          = GetSystemMetrics(virtual_desktop ? SM_CYVIRTUALSCREEN : SM_CYSCREEN);
        const LONG x               = MulDiv(mouse.lLastX, width, USHRT_MAX) + left;
        const LONG y               = MulDiv(mouse.lLastY, height, USHRT_MAX) + top;
        dx                         = absolute_known_ ? x - absolute_last_x_ : 0;
        dy                         = absolute_known_ ? y - absolute_last_y_ : 0;
        absolute_last_x_           = x;
        absolute_last_y_           = y;
        absolute_known_            = true;
    }
    if (dx == 0 && dy == 0) return;
    const qreal dpr = window_->devicePixelRatio();
    sink_.OnRelativeMotion(dx / dpr, dy / dpr);
}

}

std::unique_ptr<QtPointerLock> MakeQtPointerLock(QtRelativeMotionSink& sink) {
    return std::make_unique<RawMousePointerLock>(sink);
}
