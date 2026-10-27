#pragma once

#include "../qt_emulator_window.h"
#include "../viewport_layout.h"

#include <cstdint>
#include <memory>

class QTimer;
class QWidget;
class QtCanvas;
class QtHostWindow;
class QtStatusBar;

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

    void Raise();

    QWidget*     Window() const;
    QWidget*     CanvasWidget() const;
    QtStatusBar& Bar() const { return *bar_; }

    void SetKeyboardGrab(bool on);

    void OnUserResized() { follow_guest_ = false; }
    void OnMaximized() { follow_guest_ = false; }
    void OnDeactivated();
    void OnCanvasResized();

private:
    void BuildMenus();
    void AutoResizeToGuest();
    void FitWindowToSurface(uint32_t sw, uint32_t sh);
    void AdoptResolutionToWindowMonitor();
    void FireAutoResize();

    QtHostWindow*           window_ = nullptr;
    QtCanvas*               canvas_ = nullptr;
    QtStatusBar*            bar_    = nullptr;
    std::unique_ptr<QTimer> resize_debounce_;

    bool follow_guest_  = true;
    bool fullscreen_    = false;
    bool was_maximized_ = false;
};
