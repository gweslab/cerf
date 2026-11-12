#include "qt_emulator_window.h"

#include "cerfman/manager_engine.h"
#include "emulator_controller.h"
#include "emulator_window_host.h"
#include "guest_surface.h"
#include "nested_event_loops.h"
#include "overlay_touch_area.h"
#include "qml_dialog_waiter.h"
#include "status_bar_item.h"
#include "strip_widget_bar.h"

#include "balloon_hint.h"
#include "canvas_tabs.h"
#include "hud_selection.h"
#include "screenshots.h"
#include "shutdown_prompt.h"
#include "shutdown_teardown.h"
#include "tab_menu.h"
#include "view_rotation.h"
#include "widget_menu_builder.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/log.h>
#include <cerfcore/host/frame_renderer.h>
#include <cerfcore/host/pointer_widget.h>
#include <cerfcore/host/shutdown_host.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_framebuffer.h>

#include <QMetaObject>
#include <QQuickWindow>
#include <QTimer>

#include <utility>

REGISTER_SERVICE(QtEmulatorWindow);

namespace {

constexpr uint32_t kScreenshotHintMs = 2000;

}

QtEmulatorWindow::~QtEmulatorWindow() = default;

void QtEmulatorWindow::OpenWindow() {
    const auto& dc = emu_.Get<cerfcore::DeviceConfig>();
    MakeWindow();
    surface_->Attach(emu_, dc.board_configurable_screen_width, dc.board_configurable_screen_height);
    emu_.Get<cerffrontend::CanvasInput>().Attach(surface_);
    input_attached_ = true;
    controller_->Attach(emu_);
    if (widget_bar_) widget_bar_->Attach(emu_);
    if (status_bar_) status_bar_->Attach(emu_);
    if (overlay_area_) overlay_area_->Attach(emu_);
    ApplyPresentation();
    surface_->SetFramebufferActive(CurrentTab() == Tab::Framebuffer);
    surface_w_.store(surface_->GuestSurfaceWidth(), std::memory_order_release);
    surface_h_.store(surface_->GuestSurfaceHeight(), std::memory_order_release);
    teardown_timer_ = std::make_unique<QTimer>();
    teardown_timer_->setInterval(static_cast<int>(cerffrontend::ShutdownTeardown::kPollMs));
    teardown_timer_->callOnTimeout(gate_.Bind([this] { PollTeardown(); }));
    LOG(Lcd, "QtEmulatorWindow: opening at %ux%u\n", dc.board_configurable_screen_width,
        dc.board_configurable_screen_height);

    auto& host = emu_.Get<EmulatorWindowHost>();
    host.ShowWindow();
    native_handle_.store(static_cast<uint64_t>(window_->winId()), std::memory_order_release);
    host.PlaceWindow();
    ReleaseHeldJobs();
}

void QtEmulatorWindow::MakeWindow() {
    if (window_) return;
    window_       = qobject_cast<QQuickWindow*>(emu_.Get<ManagerEngine>().Open(QStringLiteral("EmulatorWindow"), {}));
    surface_      = window_->property("surface").value<GuestSurface*>();
    controller_   = window_->property("controller").value<EmulatorController*>();
    widget_bar_   = window_->property("widgetBar").value<StripWidgetBar*>();
    status_bar_   = window_->property("statusBar").value<StatusBarItem*>();
    overlay_area_ = window_->property("overlayArea").value<OverlayTouchArea*>();
    window_->installEventFilter(&menu_dismiss_);
}

void QtEmulatorWindow::MenuClosing() { menu_dismiss_.Arm(); }

void QtEmulatorWindow::OnShutdown() { CloseWindow(); }

void QtEmulatorWindow::CloseWindow() {
    *alive_ = false;
    if (teardown_timer_) teardown_timer_->stop();
    native_handle_.store(0, std::memory_order_release);
    if (widget_bar_) widget_bar_->Detach();
    if (status_bar_) status_bar_->Detach();
    if (overlay_area_) overlay_area_->Detach();
    if (controller_) controller_->Detach();
    if (surface_) surface_->Detach();
    if (input_attached_) emu_.Get<cerffrontend::CanvasInput>().Attach(nullptr);
    input_attached_ = false;
    delete window_.data();
}

void QtEmulatorWindow::ReleaseHeldJobs() {
    std::lock_guard<std::mutex> lock(held_mutex_);
    open_ = true;
    for (std::function<void()>& job : held_) Post(std::move(job));
    held_.clear();
}

bool QtEmulatorWindow::AdoptsHostResolution() const {
    const auto& dc = emu_.Get<cerfcore::DeviceConfig>();
    return dc.guest_additions && dc.adopt_guest_additions_resolution_for_host_screen;
}

QtEmulatorWindow::Tab QtEmulatorWindow::CurrentTab() const {
    return emu_.Get<cerffrontend::CanvasTabs>().Current();
}

void QtEmulatorWindow::SetTab(Tab tab, bool user_initiated) {
    if (!emu_.Get<cerffrontend::CanvasTabs>().Set(tab, user_initiated)) return;
    surface_->SetFramebufferActive(tab == Tab::Framebuffer);
    surface_->Repaint();
}

void QtEmulatorWindow::SetGuestSurfaceSize(uint32_t w, uint32_t h) {
    surface_->SetGuestSurfaceSize(w, h);
    surface_w_.store(surface_->GuestSurfaceWidth(), std::memory_order_release);
    surface_h_.store(surface_->GuestSurfaceHeight(), std::memory_order_release);
}

void QtEmulatorWindow::SetGuestResolution(uint32_t w, uint32_t h) {
    if (w == 0 || h == 0) return;
    if (!emu_.Get<cerfcore::CerfVirtFramebuffer>().SetHostMode(w, h)) return;
    SetGuestSurfaceSize(w, h);
}

void QtEmulatorWindow::OnLcdEnabled() {
    RunOnUiThread([this] {
        uint32_t w = 0, h = 0;
        emu_.Get<cerfcore::FrameRenderer>().PresentedSize(w, h);
        LOG(Lcd, "QtEmulatorWindow: LCD resize, presented %ux%u\n", w, h);
        if (w == 0 || h == 0) return;
        SetGuestSurfaceSize(w, h);
        RefitIfFollowingGuest();
    });
}

void QtEmulatorWindow::ApplyPresentation() {
    surface_->SetPresentation(cerffrontend::ViewPresentation{emu_.Get<cerffrontend::HudSelection>().Frame(),
                                                          emu_.Get<cerffrontend::ViewRotation>().Quarter()});
}

void QtEmulatorWindow::OnPresentationChanged() {
    RunOnUiThread([this] {
        ApplyPresentation();
        surface_->Repaint();
        emu_.Get<EmulatorWindowHost>().RefitForPresentation();
        controller_->RefreshHud();
    });
}

void QtEmulatorWindow::NotifyGuestRemoded(uint32_t w, uint32_t h) {
    RunOnUiThread([this, w, h] { SetGuestSurfaceSize(w, h); });
}

void QtEmulatorWindow::RunOnUiThread(std::function<void()> job) {
    std::lock_guard<std::mutex> lock(held_mutex_);
    if (!open_) {
        held_.push_back(std::move(job));
        return;
    }
    Post(std::move(job));
}

void QtEmulatorWindow::Post(std::function<void()> job) {
    QMetaObject::invokeMethod(
        &jobs_,
        [alive = alive_, job = gate_.Bind(std::move(job))]() mutable {
            if (*alive) job();
        },
        Qt::QueuedConnection);
}

void QtEmulatorWindow::RunOnUiThreadAfter(uint32_t delay_ms, std::function<void()> job) {
    QTimer::singleShot(static_cast<int>(delay_ms), window_.data(), gate_.Bind([job = std::move(job)] { job(); }));
}

bool QtEmulatorWindow::CaptureGuestSurface(std::vector<uint32_t>& out, uint32_t& w, uint32_t& h) {
    return surface_->CaptureSurface(out, w, h);
}

void QtEmulatorWindow::CloseRequested() {
    const bool begun = emu_.Get<cerffrontend::ShutdownPrompt>().BeginCloseRequest();
    LOG(Manager, "QtEmulatorWindow: close requested, prompt %s\n", begun ? "queued" : "already pending");
    if (!begun) return;
    RunOnUiThread([this] { RunShutdownPrompt(); });
}

void QtEmulatorWindow::RunShutdownPrompt() {
    emu_.Get<cerffrontend::ShutdownPrompt>().FinishCloseRequest(
        emu_.Get<cerfcore::ShutdownHost>().Ask(cerfcore::ShutdownTrigger::WindowClose));
}

void QtEmulatorWindow::BeginShutdownTeardown() {
    if (emu_.Get<cerffrontend::ShutdownTeardown>().Begin()) teardown_timer_->start();
}

void QtEmulatorWindow::PollTeardown() {
    switch (emu_.Get<cerffrontend::ShutdownTeardown>().Poll()) {
        case cerffrontend::ShutdownTeardown::Step::kWaiting:
            return;
        case cerffrontend::ShutdownTeardown::Step::kStopped:
            teardown_timer_->stop();
            return;
        case cerffrontend::ShutdownTeardown::Step::kWedged:
            teardown_timer_->stop();
            OnTeardownWedged();
            return;
    }
}

void QtEmulatorWindow::OnTeardownWedged() { emu_.Get<EmulatorWindowHost>().OnTeardownWedged(); }

bool QtEmulatorWindow::IsFullscreen() const { return emu_.Get<EmulatorWindowHost>().IsFullscreen(); }

void QtEmulatorWindow::ToggleFullscreen() { emu_.Get<EmulatorWindowHost>().ToggleFullscreen(); }

void QtEmulatorWindow::MatchGuestSize() { emu_.Get<EmulatorWindowHost>().MatchGuestSize(); }

void QtEmulatorWindow::RefitIfFollowingGuest() { emu_.Get<EmulatorWindowHost>().RefitIfFollowingGuest(); }

void QtEmulatorWindow::FitToResolution(uint32_t w, uint32_t h) { emu_.Get<EmulatorWindowHost>().FitToResolution(w, h); }

void QtEmulatorWindow::Raise() {
    RunOnUiThread([this] { emu_.Get<EmulatorWindowHost>().Raise(); });
}

void QtEmulatorWindow::SetKeyboardGrab(bool on) {
    RunOnUiThread([this, on] {
        if (window_) window_->setKeyboardGrabEnabled(on);
    });
}

void QtEmulatorWindow::SurfaceForCanvas(uint32_t canvas_w, uint32_t canvas_h, uint32_t& w, uint32_t& h) const {
    surface_->Layout().SurfaceFor(static_cast<int>(canvas_w), static_cast<int>(canvas_h), w, h);
}

cerffrontend::ViewportMode QtEmulatorWindow::Mode() const { return surface_->ViewportMode(); }

int QtEmulatorWindow::IntegerFactor() const { return surface_->IntegerFactor(); }

bool QtEmulatorWindow::Antialias() const { return surface_->Antialias(); }

void QtEmulatorWindow::SetViewportMode(cerffrontend::ViewportMode mode) { surface_->SetViewportMode(mode); }

void QtEmulatorWindow::SetIntegerScale(int factor) { surface_->SetIntegerScale(factor); }

void QtEmulatorWindow::SetAntialias(bool on) { surface_->SetAntialias(on); }

void QtEmulatorWindow::ReturnToManager() { window_->hide(); }

QQuickWindow* QtEmulatorWindow::Window() const { return window_.data(); }

GuestSurface* QtEmulatorWindow::Surface() const { return surface_.data(); }

EmulatorController* QtEmulatorWindow::Controller() const { return controller_.data(); }

StatusBarItem* QtEmulatorWindow::StatusBar() const { return status_bar_.data(); }

std::vector<cerffrontend::MenuItem> QtEmulatorWindow::PointerMenu() {
    using cerffrontend::MenuItem;
    std::vector<MenuItem> items;
    if (!surface_->RelativePointer()) {
        const bool cursor = surface_->CursorMode();
        items.push_back(MenuItem::Radio("Stylus", !cursor, [this] { surface_->SetCursorMode(false); }));
        items.push_back(MenuItem::Radio("Cursor", cursor, [this] { surface_->SetCursorMode(true); }));
    }
    if (auto* widget = emu_.TryGet<cerfcore::PointerWidget>()) {
        std::vector<cerffrontend::MenuItem> controls =
            emu_.Get<cerffrontend::WidgetMenuBuilder>().Build(widget->Controls());
        if (!controls.empty() && !items.empty()) items.push_back(cerffrontend::MenuItem{});
        for (cerffrontend::MenuItem& entry : controls) items.push_back(std::move(entry));
    }
    return items;
}

std::vector<cerffrontend::MenuItem> QtEmulatorWindow::GearMenu() {
    using cerffrontend::MenuItem;
    const ViewMode        view = surface_->CurrentViewMode();
    auto&                 tabs = emu_.Get<cerffrontend::TabMenu>();
    std::vector<MenuItem> items;
    items.push_back(MenuItem::Row(
        "Device", {MenuItem::IconAction("Return to my devices", "home", [this] { ReturnToManager(); }),
                   MenuItem::IconAction("Save screenshot", "photo_camera", [this] { SaveScreenshot(); }),
                   MenuItem::IconAction("Power off/reset", "power_settings_new", [this] { CloseRequested(); })}));
    items.push_back(MenuItem{});
    items.push_back(tabs.Item(Tab::Hw));
    items.push_back(tabs.Item(Tab::Framebuffer));
    items.push_back(MenuItem{});
    items.push_back(MenuItem::Radio("Fit the screen", view == ViewMode::FitScreen,
                                    [this] { surface_->SetViewMode(ViewMode::FitScreen); }));
    items.push_back(MenuItem::Radio("Fit the safe zone", view == ViewMode::FitSafeZone,
                                    [this] { surface_->SetViewMode(ViewMode::FitSafeZone); }));
    items.push_back(MenuItem::Radio("Original scale", view == ViewMode::OriginalScale,
                                    [this] { surface_->SetViewMode(ViewMode::OriginalScale); }));
    items.push_back(MenuItem{});
    items.push_back(emu_.Get<cerffrontend::ViewRotation>().MenuRow());
    return items;
}

QObject* QtEmulatorWindow::CreateDialog(const QString& type_name, const QVariantMap& properties) {
    if (!window_) {
        MakeWindow();
        emu_.Get<EmulatorWindowHost>().ShowWindow();
    }
    QVariant created;
    QMetaObject::invokeMethod(window_.data(), "createDialog", Q_RETURN_ARG(QVariant, created),
                              Q_ARG(QVariant, type_name), Q_ARG(QVariant, properties));
    return created.value<QObject*>();
}

QVariant QtEmulatorWindow::RunDialog(const QString& type_name, const QVariantMap& properties,
                                     const std::function<void(QObject*)>& opened) {
    QObject*        dialog = CreateDialog(type_name, properties);
    QmlDialogWaiter waiter;
    waiter.Watch(dialog);
    QMetaObject::invokeMethod(dialog, "open");
    if (opened) opened(dialog);
    waiter.Wait(emu_.Get<NestedEventLoops>());
    return waiter.Result();
}

QObject* QtEmulatorWindow::CreateExternalDisplay() {
    QVariant created;
    QMetaObject::invokeMethod(window_.data(), "createExternalDisplay", Q_RETURN_ARG(QVariant, created));
    return created.value<QObject*>();
}

void QtEmulatorWindow::SaveScreenshot() {
    const bool saved = emu_.Get<cerffrontend::Screenshots>().Save();
    ShowHint(saved ? QStringLiteral("Screenshot saved to Pictures/CERF") : QStringLiteral("Screenshot not saved"),
             kScreenshotHintMs, cerffrontend::BalloonHint::kCanvasBottomGap);
}

void QtEmulatorWindow::ShowHint(const QString& text, uint32_t hold_ms, int bottom_gap) {
    QMetaObject::invokeMethod(window_.data(), "showHint", Q_ARG(QVariant, text),
                              Q_ARG(QVariant, static_cast<int>(hold_ms)), Q_ARG(QVariant, bottom_gap));
}

void QtEmulatorWindow::ShowHintAt(const QString& text, uint32_t hold_ms, const QRectF& anchor) {
    QMetaObject::invokeMethod(window_.data(), "showHintAt", Q_ARG(QVariant, text),
                              Q_ARG(QVariant, static_cast<int>(hold_ms)), Q_ARG(QVariant, anchor));
}

void QtEmulatorWindow::CloseDialogs() {
    if (window_) QMetaObject::invokeMethod(window_.data(), "closeDialogs");
}
