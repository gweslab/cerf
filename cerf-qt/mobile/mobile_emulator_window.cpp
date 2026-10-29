#include "mobile_emulator_window.h"

#include "../cerfman/manager_engine.h"
#include "../nested_event_loops.h"
#include "../qt_screen_pixels.h"
#include "emulator_controller.h"
#include "guest_surface.h"
#include "mobile_widget_bar.h"
#include "qml_dialog_waiter.h"
#include "view_placement.h"

#include "../tab_menu.h"
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

MobileEmulatorWindow::~MobileEmulatorWindow() = default;

void MobileEmulatorWindow::OpenWindow() {
    const auto& dc = emu_.Get<cerfcore::DeviceConfig>();
    MakeWindow();
    surface_->Attach(emu_, dc.board_configurable_screen_width, dc.board_configurable_screen_height);
    emu_.Get<cerffrontend::CanvasInput>().Attach(surface_);
    input_attached_ = true;
    controller_->Attach(emu_);
    widget_bar_->Attach(emu_);
    AttachView(*surface_, *window_);
    LOG(Lcd, "MobileEmulatorWindow: opening at %ux%u\n", dc.board_configurable_screen_width,
        dc.board_configurable_screen_height);

    window_->showFullScreen();
    PublishNativeHandle(static_cast<uint64_t>(window_->winId()));
    AdoptResolutionToScreen();
}

void MobileEmulatorWindow::MakeWindow() {
    if (window_) return;
    window_     = qobject_cast<QQuickWindow*>(emu_.Get<ManagerEngine>().Open(QStringLiteral("EmulatorWindow"), {}));
    surface_    = window_->property("surface").value<GuestSurface*>();
    controller_ = window_->property("controller").value<EmulatorController*>();
    widget_bar_ = window_->property("widgetBar").value<MobileWidgetBar*>();
}

void MobileEmulatorWindow::OnShutdown() { CloseWindow(); }

void MobileEmulatorWindow::CloseWindow() {
    DetachView();
    if (widget_bar_) widget_bar_->Detach();
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
    items.push_back(MenuItem::Action("Return to my devices", [this] { ReturnToManager(); }));
    items.push_back(MenuItem::Action("Power off/reset", [this] { CloseRequested(); }));
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
    return items;
}

void MobileEmulatorWindow::AdoptResolutionToScreen() {
    if (!AdoptsHostResolution()) return;
    const QSize pixels = ScreenPixels(*window_->screen());
    const auto  w      = static_cast<uint32_t>(pixels.width());
    const auto  h      = static_cast<uint32_t>(pixels.height());
    if (w == 0 || h == 0) return;
    SetGuestResolution(w, h);
    LOG(Lcd, "MobileEmulatorWindow: adopt screen -> guest surface %ux%u\n", w, h);
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

void MobileEmulatorWindow::ShowHint(const QString& text, uint32_t hold_ms, int bottom_gap) {
    QMetaObject::invokeMethod(window_.data(), "showHint", Q_ARG(QVariant, text),
                              Q_ARG(QVariant, static_cast<int>(hold_ms)), Q_ARG(QVariant, bottom_gap));
}

void MobileEmulatorWindow::CloseDialogs() {
    if (window_) QMetaObject::invokeMethod(window_.data(), "closeDialogs");
}
