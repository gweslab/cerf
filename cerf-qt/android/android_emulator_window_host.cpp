#include "../emulator_window_host.h"
#include "../external_display_view.h"
#include "../guest_surface.h"
#include "../qt_emulator_window.h"
#include "../qt_screen_pixels.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/fatal.h>
#include <cerfcore/core/log.h>

#include <QPointer>
#include <QQuickWindow>
#include <QScreen>

namespace {

class ExternalDisplayBox final : public ExternalDisplayContainer {
public:
    ExternalDisplayBox(cerfcore::CerfEmulator& emu, int source_id, uint32_t w, uint32_t h)
        : box_(emu.Get<QtEmulatorWindow>().CreateExternalDisplay()),
          view_(qobject_cast<ExternalDisplayView*>(box_->property("view").value<QObject*>())) {
        view_->Attach(source_id, emu, w, h);
    }

    ~ExternalDisplayBox() override {
        if (view_) view_->Detach();
        delete box_.data();
    }

    void SetSurfaceSize(uint32_t w, uint32_t h) override {
        if (view_) view_->SetSurfaceSize(w, h);
    }

private:
    QPointer<QObject>             box_;
    QPointer<ExternalDisplayView> view_;
};

class AndroidEmulatorWindowHost : public EmulatorWindowHost {
public:
    using EmulatorWindowHost::EmulatorWindowHost;

    void ShowWindow() override { emu_.Get<QtEmulatorWindow>().Window()->showFullScreen(); }

    void PlaceWindow() override { AdoptResolutionToScreen(); }

    void Raise() override {
        QQuickWindow* window = emu_.Get<QtEmulatorWindow>().Window();
        window->showFullScreen();
        window->raise();
        window->requestActivate();
    }

    bool IsFullscreen() const override { return fullscreen_; }

    void ToggleFullscreen() override {
        QQuickWindow* window = emu_.Get<QtEmulatorWindow>().Window();
        fullscreen_          = !fullscreen_;
        if (fullscreen_) window->showFullScreen();
        else             window->showMaximized();
    }

    void MatchGuestSize() override { Refit(); }

    void RefitIfFollowingGuest() override { Refit(); }

    void FitToResolution(uint32_t, uint32_t) override { Refit(); }

    void RefitForPresentation() override { Refit(); }

    void OnTeardownWedged() override {
        cerfcore::Fatal& fatal = emu_.Get<cerfcore::Fatal>();
        fatal.Guard([&fatal] { fatal.Die("QtEmulatorWindow: the guest did not stop after close"); });
        auto& window = emu_.Get<QtEmulatorWindow>();
        window.CloseWindow();
        window.RunWedgedHandler();
    }

    std::vector<std::string>            MenuTitles() override { return {}; }
    std::vector<cerffrontend::MenuItem> Menu(int) override { return {}; }

    std::unique_ptr<ExternalDisplayContainer> OpenExternalDisplay(int source_id, const std::string&, uint32_t w,
                                                                  uint32_t h) override {
        return std::make_unique<ExternalDisplayBox>(emu_, source_id, w, h);
    }

private:
    void Refit() { emu_.Get<QtEmulatorWindow>().Surface()->Refit(); }

    void AdoptResolutionToScreen() {
        auto& window = emu_.Get<QtEmulatorWindow>();
        if (!window.AdoptsHostResolution()) return;
        GuestSurface&   surface = *window.Surface();
        const QScreen&  screen  = *window.Window()->screen();
        const QSize     logical = screen.geometry().size();
        const QMarginsF cutout  = ScreenCutoutMargins(screen);
        const QSize     region  = surface.ScreenRegionFor(logical, cutout);
        uint32_t        w       = 0;
        uint32_t        h       = 0;
        surface.Layout().SurfaceFor(region.width(), region.height(), w, h);
        if (w == 0 || h == 0) return;
        window.SetGuestResolution(w, h);
        LOG(Lcd, "QtEmulatorWindow: adopt screen %dx%d cutout %g,%g,%g,%g -> region %dx%d, guest surface %ux%u\n",
            logical.width(), logical.height(), cutout.left(), cutout.top(), cutout.right(), cutout.bottom(),
            region.width(), region.height(), w, h);
    }

    bool fullscreen_ = true;
};

}

REGISTER_SERVICE_AS(AndroidEmulatorWindowHost, EmulatorWindowHost);
