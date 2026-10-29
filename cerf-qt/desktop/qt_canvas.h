#pragma once

#include "../qt_key_input.h"
#include "qt_pointer_lock.h"
#include "qt_presenter_canvas.h"

#include "../canvas_input.h"

#include <QTimer>

#include <memory>

class QtCanvas : public QtPresenterCanvas, public cerffrontend::CanvasInputHost, public QtRelativeMotionSink {
public:
    QtCanvas(cerfcore::CerfEmulator& emu, QWidget* parent, uint32_t surf_w, uint32_t surf_h);

    void LoseMouseCapture();

    void SetMouseCapture(bool on) override;
    bool HasMouseCapture() const override { return grabbing_; }
    void FocusCanvas() override;
    void SetPointerHidden(bool hidden) override;
    bool WarpPointerTo(int x, int y) override;
    bool LockPointer() override;
    void UnlockPointer() override;
    void ClientSize(int& width, int& height) const override;
    bool HostToGuest(int x, int y, int& sx, int& sy) const override { return MapToGuest(x, y, sx, sy); }
    void ClampGuest(int& sx, int& sy) const override { ClampToGuest(sx, sy); }

    void OnRelativeMotion(double dx, double dy) override;

protected:
    void mousePressEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void leaveEvent(QEvent* event) override;
    void wheelEvent(QWheelEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    void keyReleaseEvent(QKeyEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    bool focusNextPrevChild(bool next) override;

    cerfcore::FrameSource& Source(cerfcore::CerfEmulator& emu) override;

private:
    void ApplyCursor(cerfcore::CerfEmulator& emu, int x, int y);
    void RouteMouse(cerfcore::CerfEmulator& emu, QMouseEvent* event, cerffrontend::CanvasMouse::Kind kind);
    void FireAutoResize(cerfcore::CerfEmulator& emu);

    QTimer                         resize_debounce_;
    std::unique_ptr<QtPointerLock> pointer_lock_;
    bool                           grabbing_        = false;
    bool                           pointer_hidden_  = false;
    double                         relative_rest_x_ = 0;
    double                         relative_rest_y_ = 0;
};
