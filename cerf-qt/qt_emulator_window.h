#pragma once

#include "frontend_window.h"
#include "menu_dismiss_filter.h"
#include "viewport_layout.h"
#include "widget_menu_model.h"

#include <cerfcore/core/instance_gate.h>

#include <QObject>
#include <QPointer>
#include <QRectF>
#include <QString>
#include <QVariant>
#include <QVariantMap>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

class EmulatorController;
class GuestSurface;
class OverlayTouchArea;
class QQuickWindow;
class QTimer;
class StatusBarItem;
class StripWidgetBar;

class QtEmulatorWindow : public cerffrontend::FrontendWindow {
public:
    using cerffrontend::FrontendWindow::FrontendWindow;
    ~QtEmulatorWindow() override;

    void OnShutdown() override;

    Tab      CurrentTab() const override;
    void     SetTab(Tab tab, bool user_initiated) override;
    bool     IsFullscreen() const override;
    void     ToggleFullscreen() override;
    void     MatchGuestSize() override;
    void     RefitIfFollowingGuest() override;
    void     OnPresentationChanged() override;
    void     SetGuestResolution(uint32_t w, uint32_t h) override;
    void     FitToResolution(uint32_t w, uint32_t h) override;
    void     OnLcdEnabled() override;
    void     NotifyGuestRemoded(uint32_t w, uint32_t h) override;
    uint32_t GuestSurfaceWidth() const override { return surface_w_.load(std::memory_order_acquire); }
    uint32_t GuestSurfaceHeight() const override { return surface_h_.load(std::memory_order_acquire); }
    void     SetGuestSurfaceSize(uint32_t w, uint32_t h) override;
    void     RunOnUiThread(std::function<void()> job) override;
    void     RunOnUiThreadAfter(uint32_t delay_ms, std::function<void()> job) override;
    bool     CaptureGuestSurface(std::vector<uint32_t>& out, uint32_t& w, uint32_t& h) override;
    bool     RequestShadedCapture() override;
    uint64_t NativeHandle() const override { return native_handle_.load(std::memory_order_acquire); }

    void CloseRequested();
    void BeginShutdownTeardown();
    bool AdoptsHostResolution() const;
    void OnTeardownWedged();
    void SetWedgedHandler(std::function<void()> handler) { wedged_handler_ = std::move(handler); }
    void RunWedgedHandler() const { wedged_handler_(); }

    void                                OpenWindow();
    void                                CloseWindow();
    void                                Raise();
    void                                SetKeyboardGrab(bool on);
    void SurfaceForCanvas(uint32_t canvas_w, uint32_t canvas_h, uint32_t& w, uint32_t& h) const;
    cerffrontend::ViewportMode          Mode() const;
    int                                 IntegerFactor() const;
    void                                SetViewportMode(cerffrontend::ViewportMode mode);
    void                                SetIntegerScale(int factor);
    void                                ReturnToManager();
    void                                SaveScreenshot();
    std::vector<cerffrontend::MenuItem> GearMenu();
    std::vector<cerffrontend::MenuItem> PointerMenu();
    QQuickWindow*                       Window() const;
    GuestSurface*                       Surface() const;
    EmulatorController*                 Controller() const;
    StatusBarItem*                      StatusBar() const;
    QVariant    RunDialog(const QString& type_name, const QVariantMap& properties,
                          const std::function<void(QObject*)>& opened = {});
    void        ShowHint(const QString& text, uint32_t hold_ms, int bottom_gap);
    void        ShowHintAt(const QString& text, uint32_t hold_ms, const QRectF& anchor);
    QObject*    CreateExternalDisplay();
    void        CloseDialogs();
    void        MenuClosing();

private:
    void     MakeWindow();
    QObject* CreateDialog(const QString& type_name, const QVariantMap& properties);
    void     ApplyPresentation();
    void     Post(std::function<void()> job);
    void     ReleaseHeldJobs();
    void     RunShutdownPrompt();
    void     PollTeardown();

    const cerfcore::InstanceGate gate_{emu_};

    QPointer<QQuickWindow>       window_;
    QPointer<GuestSurface>       surface_;
    QPointer<EmulatorController> controller_;
    QPointer<StripWidgetBar>     widget_bar_;
    QPointer<StatusBarItem>      status_bar_;
    QPointer<OverlayTouchArea>   overlay_area_;
    bool                         input_attached_ = false;

    std::mutex                         held_mutex_;
    std::vector<std::function<void()>> held_;
    bool                               open_ = false;
    QObject                            jobs_;
    MenuDismissFilter                  menu_dismiss_;
    std::unique_ptr<QTimer>            teardown_timer_;
    std::function<void()>              wedged_handler_;
    std::shared_ptr<bool>              alive_ = std::make_shared<bool>(true);
    std::atomic<uint32_t>              surface_w_{0};
    std::atomic<uint32_t>              surface_h_{0};
    std::atomic<uint64_t>              native_handle_{0};
};
