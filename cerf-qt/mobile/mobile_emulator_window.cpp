#include "mobile_emulator_window.h"

#include "../cerfman/manager_engine.h"
#include "../nested_event_loops.h"
#include "../qt_screen_pixels.h"
#include "emulator_controller.h"
#include "guest_surface.h"
#include "mobile_widget_bar.h"
#include "overlay_touch_area.h"
#include "qml_dialog_waiter.h"
#include "view_placement.h"

#include "../balloon_hint.h"
#include "../screenshots.h"
#include "../tab_menu.h"
#include "../view_rotation.h"
#include "../widget_menu_builder.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/fatal.h>
#include <cerfcore/core/log.h>
#include <cerfcore/host/pointer_widget.h>

#include <QMetaObject>
#include <QQuickItem>
#include <QQuickWindow>
#include <QScreen>

#include <functional>
#include <utility>

REGISTER_SERVICE(MobileEmulatorWindow);

namespace {

constexpr uint32_t kScreenshotHintMs = 2000;

}

MobileEmulatorWindow::~MobileEmulatorWindow() = default;

void MobileEmulatorWindow::OpenWindow() {
    const auto& dc = emu_.Get<cerfcore::DeviceConfig>();
    MakeWindow();
    surface_->Attach(emu_, dc.board_configurable_screen_width, dc.board_configurable_screen_height);
    emu_.Get<cerffrontend::CanvasInput>().Attach(surface_);
    input_attached_ = true;
    controller_->Attach(emu_);
    widget_bar_->Attach(emu_);
    overlay_area_->Attach(emu_);
    AttachView(*surface_, *window_);
    LOG(Lcd, "MobileEmulatorWindow: opening at %ux%u\n", dc.board_configurable_screen_width,
        dc.board_configurable_screen_height);

    window_->showFullScreen();
    PublishNativeHandle(static_cast<uint64_t>(window_->winId()));
    AdoptResolutionToScreen();
    ReleaseHeldJobs();
}

void MobileEmulatorWindow::MakeWindow() {
    if (window_) return;
    window_     = qobject_cast<QQuickWindow*>(emu_.Get<ManagerEngine>().Open(QStringLiteral("EmulatorWindow"), {}));
    surface_    = window_->property("surface").value<GuestSurface*>();
    controller_ = window_->property("controller").value<EmulatorController*>();
    widget_bar_ = window_->property("widgetBar").value<MobileWidgetBar*>();
    overlay_area_ = window_->property("overlayArea").value<OverlayTouchArea*>();
}

void MobileEmulatorWindow::OnShutdown() { CloseWindow(); }

void MobileEmulatorWindow::CloseWindow() {
    DetachView();
    if (widget_bar_) widget_bar_->Detach();
    if (overlay_area_) overlay_area_->Detach();
    if (controller_) controller_->Detach();
    if (surface_) surface_->Detach();
    if (input_attached_) emu_.Get<cerffrontend::CanvasInput>().Attach(nullptr);
    input_attached_ = false;
    delete window_.data();
}

void MobileEmulatorWindow::OnTeardownWedged() {
    cerfcore::Fatal& fatal = emu_.Get<cerfcore::Fatal>();
    fatal.Guard([&fatal] { fatal.Die("MobileEmulatorWindow: the guest did not stop after close"); });
    CloseWindow();
    wedged_handler_();
}

void MobileEmulatorWindow::ToggleFullscreen() {
    fullscreen_ = !fullscreen_;
    if (fullscreen_) window_->showFullScreen();
    else             window_->showMaximized();
}

void MobileEmulatorWindow::MatchGuestSize() { surface_->Refit(); }

void MobileEmulatorWindow::RefitIfFollowingGuest() { surface_->Refit(); }

void MobileEmulatorWindow::FitToResolution(uint32_t, uint32_t) { surface_->Refit(); }

void MobileEmulatorWindow::OnPresentationChanged() {
    QtEmulatorWindow::OnPresentationChanged();
    RunOnUiThread([this] { controller_->RefreshHud(); });
}

void MobileEmulatorWindow::Raise() {
    RunOnUiThread([this] {
        window_->showFullScreen();
        window_->raise();
        window_->requestActivate();
    });
}

void MobileEmulatorWindow::ReturnToManager() { window_->hide(); }

QQuickWindow* MobileEmulatorWindow::Window() const { return window_.data(); }

std::vector<cerffrontend::MenuItem> MobileEmulatorWindow::PointerMenu() {
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

std::vector<cerffrontend::MenuItem> MobileEmulatorWindow::GearMenu() {
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

void MobileEmulatorWindow::AdoptResolutionToScreen() {
    if (!AdoptsHostResolution()) return;
    const QScreen&  screen  = *window_->screen();
    const QSize     logical = screen.geometry().size();
    const QMarginsF cutout  = ScreenCutoutMargins(screen);
    const QSize     region  = surface_->ScreenRegionFor(logical, cutout);
    uint32_t        w       = 0;
    uint32_t        h       = 0;
    surface_->Layout().SurfaceFor(region.width(), region.height(), w, h);
    if (w == 0 || h == 0) return;
    SetGuestResolution(w, h);
    LOG(Lcd, "MobileEmulatorWindow: adopt screen %dx%d cutout %g,%g,%g,%g -> region %dx%d, guest surface %ux%u\n",
        logical.width(), logical.height(), cutout.left(), cutout.top(), cutout.right(), cutout.bottom(), region.width(),
        region.height(), w, h);
}

QObject* MobileEmulatorWindow::CreateDialog(const QString& type_name, const QVariantMap& properties) {
    if (!window_) {
        MakeWindow();
        window_->showFullScreen();
    }
    QVariant created;
    QMetaObject::invokeMethod(window_.data(), "createDialog", Q_RETURN_ARG(QVariant, created),
                              Q_ARG(QVariant, type_name), Q_ARG(QVariant, properties));
    return created.value<QObject*>();
}

QVariant MobileEmulatorWindow::RunDialog(const QString& type_name, const QVariantMap& properties,
                                         const std::function<void(QObject*)>& opened) {
    QObject*        dialog = CreateDialog(type_name, properties);
    QmlDialogWaiter waiter;
    waiter.Watch(dialog);
    QMetaObject::invokeMethod(dialog, "open");
    if (opened) opened(dialog);
    waiter.Wait(emu_.Get<NestedEventLoops>());
    return waiter.Result();
}

QQuickItem* MobileEmulatorWindow::CreateExternalDisplay() {
    QVariant created;
    QMetaObject::invokeMethod(window_.data(), "createExternalDisplay", Q_RETURN_ARG(QVariant, created));
    return qobject_cast<QQuickItem*>(created.value<QObject*>());
}

void MobileEmulatorWindow::SaveScreenshot() {
    const bool saved = emu_.Get<cerffrontend::Screenshots>().Save();
    ShowHint(saved ? QStringLiteral("Screenshot saved to Pictures/CERF") : QStringLiteral("Screenshot not saved"),
             kScreenshotHintMs, cerffrontend::BalloonHint::kCanvasBottomGap);
}

void MobileEmulatorWindow::ShowHint(const QString& text, uint32_t hold_ms, int bottom_gap) {
    QMetaObject::invokeMethod(window_.data(), "showHint", Q_ARG(QVariant, text),
                              Q_ARG(QVariant, static_cast<int>(hold_ms)), Q_ARG(QVariant, bottom_gap));
}

void MobileEmulatorWindow::CloseDialogs() {
    if (window_) QMetaObject::invokeMethod(window_.data(), "closeDialogs");
}
