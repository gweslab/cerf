#pragma once

#include "../qt_emulator_window.h"
#include "../viewport_layout.h"

#include <cstdint>

class QWidget;
class QtCanvas;
class QtHostWindow;
class QtStatusBar;
class QToolButton;

class QtMainWindow : public QtEmulatorWindow {
public:
    using QtEmulatorWindow::QtEmulatorWindow;
    ~QtMainWindow() override;

    void OnReady() override;
    void OnShutdown() override;

    cerffrontend::ViewportMode Mode() const;
    int                        IntegerFactor() const;
    bool                       Antialias() const;
    void                       SetViewportMode(cerffrontend::ViewportMode m);
    void                       SetIntegerScale(int factor);
    void                       SetAntialias(bool on);

    bool IsFullscreen() const override { return fullscreen_; }
    void ToggleFullscreen() override;
    bool FollowGuest() const { return follow_guest_; }
    void MatchGuestSize() override;
    void RefitIfFollowingGuest() override;
    void FitToResolution(uint32_t w, uint32_t h) override;
    void SurfaceForCanvas(uint32_t canvas_w, uint32_t canvas_h, uint32_t& w, uint32_t& h) const;

    void Raise();

    QWidget*     Window() const;
    QWidget*     CanvasWidget() const;
    bool         MenuBarIsNative() const;
    QtStatusBar& Bar() const { return *bar_; }

    void SetKeyboardGrab(bool on);

    void OnUserResized() { follow_guest_ = false; }
    void OnMaximized() { follow_guest_ = false; }
    void OnDeactivated();
    void OnTeardownWedged() override;
    void OnPresentationChanged() override;

private:
    void BuildMenus();
    void BuildHudButton();
    void RefreshHudButton();
    void AutoResizeToGuest();
    void FitWindowToSurface(uint32_t sw, uint32_t sh);
    void AdoptResolutionToWindowMonitor();

    QtHostWindow* window_     = nullptr;
    QtCanvas*     canvas_     = nullptr;
    QtStatusBar*  bar_        = nullptr;
    QToolButton*  hud_button_ = nullptr;

    bool input_attached_ = false;
    bool follow_guest_   = true;
    bool fullscreen_     = false;
    bool was_maximized_  = false;
};
