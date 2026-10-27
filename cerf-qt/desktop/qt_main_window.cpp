#include "qt_main_window.h"

#include "../qt_device_pixels.h"
#include "../qt_paint_resources.h"
#include "../qt_screen_pixels.h"
#include "../resource_paths_text.h"
#include "../qt_ui_thread.h"
#include "qt_canvas.h"
#include "qt_focus_policy.h"
#include "qt_host_window.h"
#include "qt_menu_builder.h"
#include "qt_status_bar.h"
#include "qt_theme.h"
#include "qt_window_fit.h"

#include "../dpi_scale.h"
#include "../frontend_config.h"
#include "host_menu_model.h"
#include "../input_capture.h"
#include "startup_scale.h"
#include "../window_title.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/log.h>
#include <cerfcore/host/guest_resize_policy.h>

#include <QApplication>
#include <QGuiApplication>
#include <QIcon>
#include <QMenu>
#include <QMenuBar>
#include <QPixmap>
#include <QScreen>
#include <QTimer>
#include <QVBoxLayout>

REGISTER_SERVICE(QtMainWindow);

namespace {

constexpr int kResizeDebounceMs = 200;

}

QtMainWindow::~QtMainWindow() = default;

void QtMainWindow::OnReady() {
    emu_.Get<QtTheme>().ApplyStyle();
    const auto& dc = emu_.Get<cerfcore::DeviceConfig>();
    LOG(Lcd, "QtMainWindow OnReady: opening at %ux%u\n", dc.board_configurable_screen_width,
        dc.board_configurable_screen_height);

    QIcon app_icon;
    for (int px : {16, 20, 24, 32, 48, 64, 256})
        app_icon.addPixmap(QPixmap::fromImage(emu_.Get<QtPaintResources>().SvgImage(CERF_LOGO_ASSET, px, px, 1.0)));
    QApplication::setWindowIcon(app_icon);
    window_ = new QtHostWindow(*this);
    window_->setWindowTitle(QString::fromStdString(emu_.Get<cerffrontend::WindowTitle>().Compose()));
    BuildMenus();

    auto* central = new QWidget(window_);
    auto* layout  = new QVBoxLayout(central);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    canvas_ = new QtCanvas(emu_, central, dc.board_configurable_screen_width, dc.board_configurable_screen_height);
    bar_    = new QtStatusBar(emu_, central);
    layout->addWidget(canvas_, 1);
    layout->addWidget(bar_, 0);
    window_->setCentralWidget(central);
    AttachView(*canvas_, *window_);

    resize_debounce_ = std::make_unique<QTimer>();
    resize_debounce_->setSingleShot(true);
    resize_debounce_->setInterval(kResizeDebounceMs);
    QObject::connect(resize_debounce_.get(), &QTimer::timeout, [this] { FireAutoResize(); });
    canvas_->SetResizeListener([this] { OnCanvasResized(); });

    const int scale = emu_.Get<cerffrontend::StartupScale>().Factor(
        qRound(cerffrontend::kDefaultDpi * QGuiApplication::primaryScreen()->devicePixelRatio()));
    if (scale > cerffrontend::FrontendConfig::kOriginalScale) canvas_->SetIntegerScale(scale);

    emu_.Get<QtFocusPolicy>().Show(window_);
    PublishNativeHandle(static_cast<uint64_t>(window_->winId()));
    AdoptResolutionToWindowMonitor();
    FitWindowToSurface(static_cast<uint32_t>(canvas_->ContentWidth()),
                       static_cast<uint32_t>(canvas_->ContentHeight()));
    emu_.Get<QtFocusPolicy>().Focus(canvas_);
}

void QtMainWindow::OnShutdown() {
    DetachView();
    if (resize_debounce_) resize_debounce_->stop();
    delete window_;
    window_ = nullptr;
    canvas_ = nullptr;
    bar_    = nullptr;
}

void QtMainWindow::BuildMenus() {
    auto& model = emu_.Get<cerffrontend::HostMenuModel>();
    for (int i = 0; i < cerffrontend::HostMenuModel::kMenuCount; ++i) {
        QMenu* menu = window_->menuBar()->addMenu(QString::fromUtf8(model.Title(i)));
        emu_.Get<QtMenuBuilder>().Bind(menu, [this, i] {
            return emu_.Get<cerffrontend::HostMenuModel>().Build(i);
        });
    }
}

QWidget* QtMainWindow::Window() const { return window_; }

QWidget* QtMainWindow::CanvasWidget() const { return canvas_; }

cerffrontend::ViewportMode QtMainWindow::Mode() const { return canvas_->Mode(); }
int  QtMainWindow::IntegerFactor() const { return canvas_->IntegerFactor(); }
bool QtMainWindow::Antialias() const { return canvas_->Antialias(); }
void QtMainWindow::SetViewportMode(cerffrontend::ViewportMode m) { canvas_->SetViewportMode(m); }
void QtMainWindow::SetIntegerScale(int factor) { canvas_->SetIntegerScale(factor); }
void QtMainWindow::SetAntialias(bool on) { canvas_->SetAntialias(on); }

void QtMainWindow::FitToResolution(uint32_t sw, uint32_t sh) {
    if (!window_ || sw == 0 || sh == 0) return;
    if (window_->isMaximized()) return;
    FitWindowToSurface(sw, sh);
}

void QtMainWindow::Raise() {
    RunOnUiThread([this] {
        if (window_->isMinimized()) window_->showNormal();
        window_->raise();
        window_->activateWindow();
    });
}

void QtMainWindow::AdoptResolutionToWindowMonitor() {
    if (!AdoptsHostResolution()) return;
    const QSize work   = ScreenWorkAreaPixels(*window_->screen());
    const QSize chrome = WindowChrome(*window_, *canvas_);
    const qreal dpr    = window_->devicePixelRatioF();
    const int   surf_w = work.width() - DeviceExtent(chrome.width(), dpr);
    const int   surf_h = work.height() - DeviceExtent(chrome.height(), dpr);
    if (surf_w < 1 || surf_h < 1) return;
    SetGuestResolution(static_cast<uint32_t>(surf_w), static_cast<uint32_t>(surf_h));
    LOG(Lcd, "QtMainWindow: adopt fit monitor work=%dx%d -> guest surface %dx%d\n", work.width(),
        work.height(), surf_w, surf_h);
}

void QtMainWindow::FitWindowToSurface(uint32_t sw, uint32_t sh) {
    if (!window_ || sw == 0 || sh == 0 || fullscreen_) return;
    const WindowFit fit = FitAroundContent(*window_, *canvas_, sw, sh);
    if (window_->isMaximized()) window_->showNormal();
    window_->ResizeTo(fit.client);
    window_->move(fit.position);
}

void QtMainWindow::AutoResizeToGuest() {
    const int sw = canvas_->ContentWidth();
    const int sh = canvas_->ContentHeight();
    if (sw <= 0 || sh <= 0) return;
    FitWindowToSurface(static_cast<uint32_t>(sw), static_cast<uint32_t>(sh));
    LOG(Lcd, "QtMainWindow: matched guest size %dx%d\n", sw, sh);
}

void QtMainWindow::MatchGuestSize() {
    follow_guest_ = true;
    AutoResizeToGuest();
}

void QtMainWindow::RefitIfFollowingGuest() {
    if (follow_guest_) AutoResizeToGuest();
}

void QtMainWindow::ToggleFullscreen() {
    if (!window_) return;
    if (!fullscreen_) {
        was_maximized_ = window_->isMaximized();
        fullscreen_    = true;
        window_->menuBar()->hide();
        bar_->hide();
        window_->showFullScreen();
        emu_.Get<QtFocusPolicy>().Raise(window_);
        return;
    }
    fullscreen_ = false;
    window_->menuBar()->show();
    bar_->show();
    if (was_maximized_) window_->showMaximized();
    else                window_->showNormal();
}

void QtMainWindow::SetKeyboardGrab(bool on) {
    if (!OnUiThread()) {
        RunOnUiThread([this, on] { SetKeyboardGrab(on); });
        return;
    }
    if (!canvas_) return;
    if (on) canvas_->grabKeyboard();
    else    canvas_->releaseKeyboard();
}

void QtMainWindow::OnDeactivated() {
    emu_.Get<cerffrontend::InputCapture>().OnFocusLost();
    canvas_->LoseMouseCapture();
}

void QtMainWindow::OnCanvasResized() {
    auto* ar = emu_.TryGet<cerfcore::GuestResizePolicy>();
    if (ar && ar->Enabled() && !window_->isMinimized()) resize_debounce_->start();
}

void QtMainWindow::FireAutoResize() {
    const qreal dpr = canvas_->Dpr();
    if (auto* ar = emu_.TryGet<cerfcore::GuestResizePolicy>())
        ar->OnUserResizeEnd(static_cast<uint32_t>(DeviceExtent(canvas_->width(), dpr)),
                            static_cast<uint32_t>(DeviceExtent(canvas_->height(), dpr)));
}
