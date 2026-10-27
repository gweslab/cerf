#pragma once

#include "../qt_key_input.h"
#include "qt_presenter_canvas.h"

#include "../canvas_input.h"

class QtCanvas : public QtPresenterCanvas, public cerffrontend::CanvasInputHost {
public:
    QtCanvas(cerfcore::CerfEmulator& emu, QWidget* parent, uint32_t surf_w, uint32_t surf_h);
    ~QtCanvas() override;

    void LoseMouseCapture();

    void SetMouseCapture(bool on) override;
    bool HasMouseCapture() const override { return grabbing_; }
    void FocusCanvas() override;
    void SetPointerHidden(bool hidden) override;
    void WarpPointerTo(int x, int y) override;
    void ClientSize(int& width, int& height) const override;
    bool HostToGuest(int x, int y, int& sx, int& sy) const override { return MapToGuest(x, y, sx, sy); }
    void ClampGuest(int& sx, int& sy) const override { ClampToGuest(sx, sy); }

protected:
    void mousePressEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void wheelEvent(QWheelEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    void keyReleaseEvent(QKeyEvent* event) override;
    bool focusNextPrevChild(bool next) override;

private:
    void ApplyCursor(int x, int y);
    void RouteMouse(QMouseEvent* event, cerffrontend::CanvasMouse::Kind kind);

    bool grabbing_       = false;
    bool pointer_hidden_ = false;
};
