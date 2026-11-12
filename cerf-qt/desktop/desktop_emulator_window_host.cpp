#include "content_window_state.h"
#include "desktop_guest_follow.h"
#include "external_display_window.h"
#include "global_menu_bar.h"
#include "host_menu_model.h"
#include "qt_focus_policy.h"
#include "qt_window_fit.h"
#include "startup_scale.h"

#include "../canvas_input.h"
#include "../dpi_scale.h"
#include "../emulator_controller.h"
#include "../emulator_window_host.h"
#include "../frontend_config.h"
#include "../guest_surface.h"
#include "../input_capture.h"
#include "../native_menu_bar.h"
#include "../qt_device_pixels.h"
#include "../qt_emulator_window.h"
#include "../qt_screen_pixels.h"
#include "../window_title.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/instance_gate.h>
#include <cerfcore/core/log.h>
#include <cerfcore/platform/host_process.h>

#include <QEvent>
#include <QGuiApplication>
#include <QQuickWindow>
#include <QResizeEvent>
#include <QScreen>
#include <QWindowStateChangeEvent>

#include <memory>

namespace {

class DesktopWindowEvents final : public QObject {
public:
    explicit DesktopWindowEvents(cerfcore::CerfEmulator& emu) : gate_(emu) {}

protected:
    bool eventFilter(QObject* watched, QEvent* event) override {
        switch (event->type()) {
            case QEvent::Close:
                event->ignore();
                gate_.Run([](cerfcore::CerfEmulator& emu) { emu.Get<QtEmulatorWindow>().CloseRequested(); });
                return true;
            case QEvent::WindowStateChange: {
                const auto*            change = static_cast<QWindowStateChangeEvent*>(event);
                const Qt::WindowStates now    = static_cast<QWindow*>(watched)->windowStates();
                gate_.Run([&](cerfcore::CerfEmulator& emu) {
                    emu.Get<DesktopGuestFollow>().OnStateChange(change->oldState(), now);
                });
                break;
            }
            case QEvent::Resize:
                if (event->spontaneous()) {
                    const QSize size = static_cast<QResizeEvent*>(event)->size();
                    gate_.Run([&](cerfcore::CerfEmulator& emu) { emu.Get<DesktopGuestFollow>().OnResized(size); });
                }
                break;
            default:
                break;
        }
        return QObject::eventFilter(watched, event);
    }

private:
    cerfcore::InstanceGate gate_;
};

class DesktopEmulatorWindowHost : public EmulatorWindowHost {
public:
    using EmulatorWindowHost::EmulatorWindowHost;

    void ShowWindow() override {
        QQuickWindow* window = emu_.Get<QtEmulatorWindow>().Window();
        if (shown_) return;
        shown_ = true;
        window->setTitle(QString::fromStdString(emu_.Get<cerffrontend::WindowTitle>().Compose()));
        events_ = std::make_unique<DesktopWindowEvents>(emu_);
        window->installEventFilter(events_.get());
        QObject::connect(window, &QWindow::activeChanged, events_.get(), gate_.Bind([this, window] {
            if (!window->isActive()) OnDeactivated();
        }));
        if (NativeMenuBar::Active()) new GlobalMenuBar(*window, *emu_.Get<QtEmulatorWindow>().Controller());
        emu_.Get<QtFocusPolicy>().Show(*window);
    }

    void PlaceWindow() override {
        GuestSurface& surface = *emu_.Get<QtEmulatorWindow>().Surface();
        const int     scale   = emu_.Get<cerffrontend::StartupScale>().Factor(
            qRound(cerffrontend::kDefaultDpi * QGuiApplication::primaryScreen()->devicePixelRatio()));
        if (scale > cerffrontend::FrontendConfig::kOriginalScale) surface.SetIntegerScale(scale);
        AdoptResolutionToWindowMonitor();
        FitWindowToSurface(static_cast<uint32_t>(surface.Layout().ContentWidth()),
                           static_cast<uint32_t>(surface.Layout().ContentHeight()));
        emu_.Get<DesktopGuestFollow>().Placed();
        emu_.Get<QtFocusPolicy>().Focus(surface);
    }

    void Raise() override {
        QQuickWindow* window = emu_.Get<QtEmulatorWindow>().Window();
        if (window->windowStates().testFlag(Qt::WindowMinimized)) {
            auto& follow = emu_.Get<DesktopGuestFollow>();
            follow.ExpectStates(Qt::WindowNoState);
            const DesktopGuestFollow::Request request(follow);
            window->showNormal();
        }
        window->raise();
        window->requestActivate();
    }

    bool IsFullscreen() const override { return chrome_.IsFullscreen(); }

    void ToggleFullscreen() override {
        QQuickWindow* window = emu_.Get<QtEmulatorWindow>().Window();
        auto&         follow = emu_.Get<DesktopGuestFollow>();
        follow.ExpectStates(chrome_.ToggledStates());
        if (const std::optional<QSize> restored = chrome_.RestoredSize())
            follow.ExpectResize(window->geometry().size(), *restored);
        {
            const DesktopGuestFollow::Request request(follow);
            chrome_.ToggleFullscreen(*window);
        }
        if (chrome_.IsFullscreen()) emu_.Get<QtFocusPolicy>().Raise(*window);
        follow.ArmLiveResize();
    }

    void MatchGuestSize() override {
        emu_.Get<DesktopGuestFollow>().Follow();
        AutoResizeToGuest();
    }

    void RefitIfFollowingGuest() override {
        const auto& follow = emu_.Get<DesktopGuestFollow>();
        if (follow.FollowsGuest() && !follow.InRequest()) AutoResizeToGuest();
    }

    void FitToResolution(uint32_t sw, uint32_t sh) override {
        auto& win = emu_.Get<QtEmulatorWindow>();
        if (sw == 0 || sh == 0) return;
        if (win.Window()->windowStates().testFlag(Qt::WindowMaximized)) return;
        int content_w = 0;
        int content_h = 0;
        win.Surface()->Layout().ContentFor(sw, sh, content_w, content_h);
        LOG(Lcd, "DesktopEmulatorWindowHost: fit to surface %ux%u -> content %dx%d\n", sw, sh, content_w, content_h);
        FitWindowToSurface(static_cast<uint32_t>(content_w), static_cast<uint32_t>(content_h));
    }

    void RefitForPresentation() override {
        auto& win    = emu_.Get<QtEmulatorWindow>();
        auto& follow = emu_.Get<DesktopGuestFollow>();
        if (chrome_.IsFullscreen() || win.Window()->windowStates().testFlag(Qt::WindowMaximized)) {
            follow.ArmLiveResize();
            return;
        }
        if (!follow.FollowsGuest() && !win.Surface()->Layout().FixedScale() && !follow.LiveResizeOn()) return;
        if (!AutoResizeToGuest()) follow.ArmLiveResize();
    }

    void OnTeardownWedged() override {
        cerfcore::Log::Close();
        cerfcore::host_platform::ExitProcessNow(cerfcore::CERF_FATAL_RUNTIME_ERROR);
    }

    std::vector<std::string> MenuTitles() override {
        auto&                    model = emu_.Get<cerffrontend::HostMenuModel>();
        std::vector<std::string> titles;
        for (int i = 0; i < cerffrontend::HostMenuModel::kMenuCount; ++i) titles.emplace_back(model.Title(i));
        return titles;
    }

    std::vector<cerffrontend::MenuItem> Menu(int index) override {
        return emu_.Get<cerffrontend::HostMenuModel>().Build(index);
    }

    std::unique_ptr<ExternalDisplayContainer> OpenExternalDisplay(int source_id, const std::string& title, uint32_t w,
                                                                  uint32_t h) override {
        return std::make_unique<ExternalDisplayWindow>(emu_, source_id, QString::fromStdString(title), w, h);
    }

private:
    void AdoptResolutionToWindowMonitor() {
        auto& win = emu_.Get<QtEmulatorWindow>();
        if (!win.AdoptsHostResolution()) return;
        QQuickWindow& window  = *win.Window();
        GuestSurface& surface = *win.Surface();
        const QSize   work    = ScreenWorkAreaPixels(*window.screen());
        const QSize   chrome  = WindowChrome(window);
        const qreal   dpr     = window.devicePixelRatio();
        uint32_t      surf_w  = 0;
        uint32_t      surf_h  = 0;
        surface.Layout().SurfaceFor(work.width() - DeviceExtent(chrome.width(), dpr),
                                    work.height() - DeviceExtent(chrome.height(), dpr), surf_w, surf_h);
        if (surf_w < 1 || surf_h < 1) return;
        win.SetGuestResolution(surf_w, surf_h);
        LOG(Lcd, "DesktopEmulatorWindowHost: adopt fit monitor work=%dx%d -> guest surface %ux%u\n", work.width(),
            work.height(), surf_w, surf_h);
    }

    bool FitWindowToSurface(uint32_t sw, uint32_t sh) {
        auto&                          win    = emu_.Get<QtEmulatorWindow>();
        QQuickWindow&                  window = *win.Window();
        const std::optional<WindowFit> fit    = chrome_.PlanFit(window, sw, sh);
        if (!fit) return true;
        auto& follow = emu_.Get<DesktopGuestFollow>();
        if (window.windowStates().testFlag(Qt::WindowMaximized)) follow.ExpectStates(Qt::WindowNoState);
        follow.ExpectResize(window.geometry().size(), fit->client);
        const DesktopGuestFollow::Request request(follow);
        chrome_.ApplyFit(window, *fit);
        return fit->whole;
    }

    bool AutoResizeToGuest() {
        GuestSurface& surface = *emu_.Get<QtEmulatorWindow>().Surface();
        const int     sw      = surface.Layout().ContentWidth();
        const int     sh      = surface.Layout().ContentHeight();
        if (sw <= 0 || sh <= 0) return true;
        const bool whole = FitWindowToSurface(static_cast<uint32_t>(sw), static_cast<uint32_t>(sh));
        LOG(Lcd, "DesktopEmulatorWindowHost: matched guest size %dx%d%s\n", sw, sh,
            whole ? "" : ", clamped to the screen");
        return whole;
    }

    void OnDeactivated() {
        emu_.Get<cerffrontend::InputCapture>().OnFocusLost();
        emu_.Get<cerffrontend::CanvasInput>().OnPointerLost();
    }

    const cerfcore::InstanceGate gate_{emu_};
    std::unique_ptr<QObject>     events_;
    ContentWindowState           chrome_;
    bool                         shown_ = false;
};

}

REGISTER_SERVICE_AS(DesktopEmulatorWindowHost, EmulatorWindowHost);
