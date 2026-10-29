#include "qt_external_display.h"

#include "../qt_key_input.h"
#include "../qt_ui_thread_calls.h"
#include "qt_focus_policy.h"
#include "qt_menu_builder.h"
#include "qt_presenter_canvas.h"
#include "qt_window_fit.h"

#include "../external_display_sources.h"
#include "../frontend_window.h"
#include "../host_key_binding.h"
#include "../screenshots.h"
#include "viewport_menu.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/instance_gate.h>

#include <QCloseEvent>
#include <QKeyEvent>
#include <QMainWindow>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QPointer>

#include "../host_virtual_keys.h"
#include "../present_timing.h"

#include <memory>

namespace {

constexpr int kMinWidth  = 160;
constexpr int kMinHeight = 120;

class ExternalCanvas : public QtPresenterCanvas {
public:
    ExternalCanvas(cerfcore::CerfEmulator& emu, QWidget* parent, int source_id, uint32_t surf_w, uint32_t surf_h)
        : QtPresenterCanvas(emu, parent, surf_w, surf_h, cerffrontend::kDefaultPresentIntervalMs),
          source_id_(source_id) {}

protected:
    cerfcore::FrameSource& Source(cerfcore::CerfEmulator& emu) override {
        return emu.Get<ExternalDisplaySources>().Source(source_id_);
    }

private:
    int source_id_;
};

}

class QtExternalWindow : public QMainWindow, public cerffrontend::ViewportMenuTarget {
public:
    QtExternalWindow(cerfcore::CerfEmulator& emu, int source_id, QString title, uint32_t surf_w, uint32_t surf_h)
        : gate_(emu), source_id_(source_id) {
        setWindowTitle(title);
        setMinimumSize(kMinWidth, kMinHeight);
        canvas_ = new ExternalCanvas(emu, this, source_id, surf_w, surf_h);
        setCentralWidget(canvas_);
        QMenu* view = menuBar()->addMenu(QStringLiteral("View"));
        emu.Get<QtMenuBuilder>().Bind(view, [this](cerfcore::CerfEmulator& menu_emu) {
            std::vector<cerffrontend::MenuItem> items;
            menu_emu.Get<cerffrontend::ViewportMenu>().Append(items, *this);
            return items;
        });
    }

    void SetSurface(uint32_t w, uint32_t h) {
        if (w == 0 || h == 0) return;
        canvas_->SetGuestSurfaceSize(w, h);
        FitToSurface(static_cast<uint32_t>(canvas_->ContentWidth()),
                     static_cast<uint32_t>(canvas_->ContentHeight()));
    }

    void FitToSurface(uint32_t sw, uint32_t sh) {
        if (sw == 0 || sh == 0 || fullscreen_) return;
        const WindowFit fit = FitAroundContent(*this, *canvas_, sw, sh);
        if (isMaximized()) showNormal();
        resize(fit.client);
        move(fit.position);
    }

    void AllowClose() { closing_ = true; }

    cerffrontend::ViewportMode Mode() const override { return canvas_->Mode(); }
    int                        IntegerFactor() const override { return canvas_->IntegerFactor(); }
    bool                       Antialias() const override { return canvas_->Antialias(); }
    void SetViewportMode(cerffrontend::ViewportMode m) override { canvas_->SetViewportMode(m); }
    void SetIntegerScale(int factor) override { canvas_->SetIntegerScale(factor); }
    void SetAntialias(bool on) override { canvas_->SetAntialias(on); }
    bool IsFullscreen() const override { return fullscreen_; }

    void ToggleFullscreen() override {
        if (!fullscreen_) {
            was_maximized_ = isMaximized();
            fullscreen_    = true;
            menuBar()->hide();
            showFullScreen();
            gate_.Run([this](cerfcore::CerfEmulator& emu) { emu.Get<QtFocusPolicy>().Raise(this); });
            return;
        }
        fullscreen_ = false;
        menuBar()->show();
        if (was_maximized_) showMaximized();
        else                showNormal();
    }

    void SaveScreenshot() override {
        std::vector<uint32_t> px;
        uint32_t              w = 0, h = 0;
        if (!canvas_->CaptureSurface(px, w, h)) return;
        gate_.Run([&](cerfcore::CerfEmulator& emu) {
            emu.Get<cerffrontend::Screenshots>().SavePixels(px, w, h, windowTitle().toStdString());
        });
    }

    void CopyScreenshot() override {
        std::vector<uint32_t> px;
        uint32_t              w = 0, h = 0;
        if (!canvas_->CaptureSurface(px, w, h)) return;
        gate_.Run([&](cerfcore::CerfEmulator& emu) { emu.Get<cerffrontend::Screenshots>().CopyPixels(px, w, h); });
    }

    void AfterModeChange(bool integer_scale) override {
        if (integer_scale)
            FitToSurface(static_cast<uint32_t>(canvas_->ContentWidth()),
                         static_cast<uint32_t>(canvas_->ContentHeight()));
    }

protected:
    void closeEvent(QCloseEvent* event) override {
        if (closing_) {
            event->accept();
            return;
        }
        event->ignore();
        if (QMessageBox::question(this, windowTitle(), QStringLiteral("Eject VGA card?")) != QMessageBox::Yes) return;
        gate_.Run([this](cerfcore::CerfEmulator& emu) {
            emu.Get<cerffrontend::FrontendWindow>().RunOnUiThread(
                [&sources = emu.Get<ExternalDisplaySources>(), id = source_id_] { sources.Eject(id); });
        });
    }

    void keyPressEvent(QKeyEvent* event) override {
        gate_.Run([this, event](cerfcore::CerfEmulator& emu) { RouteKey(emu, event, false); });
    }
    void keyReleaseEvent(QKeyEvent* event) override {
        gate_.Run([this, event](cerfcore::CerfEmulator& emu) { RouteKey(emu, event, true); });
    }

private:
    void RouteKey(cerfcore::CerfEmulator& emu, QKeyEvent* event, bool key_up) {
        if (key_up && event->isAutoRepeat()) return;
        QtHostKey key;
        auto&     keys = emu.Get<QtKeyInput>();
        if (!keys.Translate(event, key)) return;
        keys.ForEachTransition(key, key_up, [&](bool up) {
            keys.Note(key, up);
            if (!up && key.vk == cerffrontend::kVkF && emu.Get<cerffrontend::HostKeyBinding>().AllMembersDownNow())
                ToggleFullscreen();
        });
    }

    cerfcore::InstanceGate gate_;
    int                    source_id_;
    QtPresenterCanvas*     canvas_        = nullptr;
    bool                   fullscreen_    = false;
    bool                   was_maximized_ = false;
    bool                   closing_       = false;
};

QtExternalDisplay::QtExternalDisplay(cerfcore::CerfEmulator& emu, cerfcore::FrameSource& source,
                                     QString title, std::function<void()> on_eject)
    : emu_(emu), source_(source), title_(std::move(title)), on_eject_(std::move(on_eject)) {}

QtExternalDisplay::~QtExternalDisplay() { Close(); }

void QtExternalDisplay::Open(uint32_t surf_w, uint32_t surf_h) {
    if (open_.exchange(true, std::memory_order_acq_rel)) return;
    source_id_ = emu_.Get<ExternalDisplaySources>().Add(source_, on_eject_);
    emu_.Get<QtUiThreadCalls>().Run([this, surf_w, surf_h] {
        window_ = new QtExternalWindow(emu_, source_id_, title_, surf_w, surf_h);
        emu_.Get<QtFocusPolicy>().Show(window_);
        window_->FitToSurface(surf_w, surf_h);
        emu_.Get<QtFocusPolicy>().Focus(window_->centralWidget());
    });
}

void QtExternalDisplay::Close() {
    if (!open_.exchange(false, std::memory_order_acq_rel)) return;
    emu_.Get<QtUiThreadCalls>().Run([this] {
        if (!window_) return;
        window_->AllowClose();
        delete window_.data();
        window_ = nullptr;
    });
    emu_.Get<ExternalDisplaySources>().Remove(source_id_);
}

void QtExternalDisplay::SetSurfaceSize(uint32_t w, uint32_t h) {
    emu_.Get<QtUiThreadCalls>().Run([this, w, h] {
        if (window_) window_->SetSurface(w, h);
    });
}
