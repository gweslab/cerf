#include "qt_main_window.h"

#include "qt_canvas.h"
#include "qt_device_pixels.h"
#include "qt_focus_policy.h"
#include "qt_host_window.h"
#include "qt_menu_builder.h"
#include "qt_paint_resources.h"
#include "qt_shutdown_dialog.h"
#include "qt_status_bar.h"
#include "qt_theme.h"

#include <cerffrontend/canvas_tabs.h>
#include <cerffrontend/dpi_scale.h>
#include <cerffrontend/guest_auto_resize.h>
#include <cerffrontend/host_menu_model.h>
#include <cerffrontend/input_capture.h>
#include <cerffrontend/shutdown_prompt.h>
#include <cerffrontend/shutdown_teardown.h>
#include <cerffrontend/startup_scale.h>
#include <cerffrontend/status_bar.h>
#include <cerffrontend/window_title.h>

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/fatal.h>
#include <cerfcore/core/log.h>
#include <cerfcore/host/frame_renderer.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_framebuffer.h>
#include <cerfcore/platform/host_process.h>

#include <QApplication>
#include <QGuiApplication>
#include <QIcon>
#include <QMenu>
#include <QMenuBar>
#include <QMetaObject>
#include <QPixmap>
#include <QScreen>
#include <QThread>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>

REGISTER_SERVICE_AS(QtMainWindow, cerffrontend::FrontendWindow);

QtMainWindow::~QtMainWindow() = default;

void QtMainWindow::OnReady() {
    emu_.Get<QtTheme>().ApplyToApplication();
    const auto& dc     = emu_.Get<cerfcore::DeviceConfig>();
    initial_surface_w_ = dc.board_configurable_screen_width;
    initial_surface_h_ = dc.board_configurable_screen_height;
    LOG(Lcd, "QtMainWindow OnReady: opening at %ux%u\n", initial_surface_w_, initial_surface_h_);

    QIcon app_icon;
    for (int px : {16, 20, 24, 32, 48, 64, 256})
        app_icon.addPixmap(QPixmap::fromImage(emu_.Get<QtPaintResources>().SvgImage("cerf_running", px, px)));
    QApplication::setWindowIcon(app_icon);
    window_ = new QtHostWindow(*this);
    window_->setWindowTitle(QString::fromStdString(emu_.Get<cerffrontend::WindowTitle>().Compose()));
    BuildMenus();

    auto* central = new QWidget(window_);
    auto* layout  = new QVBoxLayout(central);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    canvas_ = new QtCanvas(emu_, central, initial_surface_w_, initial_surface_h_);
    bar_    = new QtStatusBar(emu_, central);
    layout->addWidget(canvas_, 1);
    layout->addWidget(bar_, 0);
    window_->setCentralWidget(central);
    surface_w_.store(canvas_->GuestSurfaceWidth(), std::memory_order_release);
    surface_h_.store(canvas_->GuestSurfaceHeight(), std::memory_order_release);

    teardown_timer_ = std::make_unique<QTimer>();
    teardown_timer_->setInterval(static_cast<int>(cerffrontend::ShutdownTeardown::kPollMs));
    QObject::connect(teardown_timer_.get(), &QTimer::timeout, [this] { PollTeardown(); });
    resize_debounce_ = std::make_unique<QTimer>();
    resize_debounce_->setSingleShot(true);
    resize_debounce_->setInterval(static_cast<int>(cerffrontend::GuestAutoResize::kDebounceMs));
    QObject::connect(resize_debounce_.get(), &QTimer::timeout, [this] { FireAutoResize(); });
    canvas_->SetResizeListener([this] { OnCanvasResized(); });

    const int scale = emu_.Get<cerffrontend::StartupScale>().Factor(
        qRound(cerffrontend::kDefaultDpi * QGuiApplication::primaryScreen()->devicePixelRatio()));
    if (scale > 1) canvas_->SetIntegerScale(scale);

    emu_.Get<QtFocusPolicy>().Show(window_);
    native_handle_.store(static_cast<uint64_t>(window_->winId()), std::memory_order_release);
    AdoptResolutionToWindowMonitor();
    FitWindowToSurface(static_cast<uint32_t>(canvas_->ContentWidth()),
                       static_cast<uint32_t>(canvas_->ContentHeight()));
    emu_.Get<QtFocusPolicy>().Focus(canvas_);
}

void QtMainWindow::OnShutdown() {
    if (teardown_timer_) teardown_timer_->stop();
    if (resize_debounce_) resize_debounce_->stop();
    delete window_;
    window_ = nullptr;
    canvas_ = nullptr;
    bar_    = nullptr;
    native_handle_.store(0, std::memory_order_release);
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

bool QtMainWindow::OnUiThread() const {
    return QThread::currentThread() == QCoreApplication::instance()->thread();
}

QtMainWindow::Tab QtMainWindow::CurrentTab() const {
    return emu_.Get<cerffrontend::CanvasTabs>().Current();
}

void QtMainWindow::SetTab(Tab tab, bool user_initiated) {
    if (!emu_.Get<cerffrontend::CanvasTabs>().Set(tab, user_initiated)) return;
    canvas_->SetFramebufferActive(tab == Tab::Framebuffer);
    canvas_->update();
}

cerffrontend::ViewportMode QtMainWindow::Mode() const { return canvas_->Mode(); }
int  QtMainWindow::IntegerFactor() const { return canvas_->IntegerFactor(); }
bool QtMainWindow::Antialias() const { return canvas_->Antialias(); }
void QtMainWindow::SetViewportMode(cerffrontend::ViewportMode m) { canvas_->SetViewportMode(m); }
void QtMainWindow::SetIntegerScale(int factor) { canvas_->SetIntegerScale(factor); }
void QtMainWindow::SetAntialias(bool on) { canvas_->SetAntialias(on); }

void QtMainWindow::SetGuestSurfaceSize(uint32_t w, uint32_t h) {
    canvas_->SetGuestSurfaceSize(w, h);
    surface_w_.store(canvas_->GuestSurfaceWidth(), std::memory_order_release);
    surface_h_.store(canvas_->GuestSurfaceHeight(), std::memory_order_release);
}

void QtMainWindow::SetGuestResolution(uint32_t w, uint32_t h) {
    if (w == 0 || h == 0) return;
    emu_.Get<cerfcore::CerfVirtFramebuffer>().ApplyGuestMode(w, h);
    SetGuestSurfaceSize(w, h);
}

void QtMainWindow::FitToResolution(uint32_t sw, uint32_t sh) {
    if (!window_ || sw == 0 || sh == 0) return;
    if (window_->isMaximized()) return;
    FitWindowToSurface(sw, sh);
}

void QtMainWindow::OnLcdEnabled() {
    RunOnUiThread([this] {
        uint32_t w = 0, h = 0;
        emu_.Get<cerfcore::FrameRenderer>().PresentedSize(w, h);
        LOG(Lcd, "QtMainWindow: LCD resize, presented %ux%u\n", w, h);
        if (w == 0 || h == 0) return;
        SetGuestSurfaceSize(w, h);
        if (follow_guest_) AutoResizeToGuest();
    });
}

void QtMainWindow::NotifyGuestRemoded(uint32_t w, uint32_t h) {
    RunOnUiThread([this, w, h] { SetGuestResolution(w, h); });
}

void QtMainWindow::RunOnUiThread(std::function<void()> job) {
    if (!job) return;
    QMetaObject::invokeMethod(QCoreApplication::instance(), [this, job = std::move(job)] {
        if (window_) job();
    }, Qt::QueuedConnection);
}

void QtMainWindow::Raise() {
    RunOnUiThread([this] {
        if (window_->isMinimized()) window_->showNormal();
        window_->raise();
        window_->activateWindow();
    });
}

bool QtMainWindow::RunOnUiThreadAfter(uint32_t delay_ms, std::function<void()> job) {
    if (!job || !window_) return false;
    if (!OnUiThread()) emu_.Get<cerfcore::Fatal>().Die("QtMainWindow::RunOnUiThreadAfter off the UI thread");
    QTimer::singleShot(static_cast<int>(delay_ms), window_, std::move(job));
    return true;
}

bool QtMainWindow::CaptureGuestSurface(std::vector<uint32_t>& out, uint32_t& w, uint32_t& h) {
    return canvas_->CaptureSurface(out, w, h);
}

void QtMainWindow::ChromeExtent(int& extra_w, int& extra_h) const {
    const QSize frame = window_->frameGeometry().size() - window_->geometry().size();
    extra_w           = frame.width();
    extra_h           = frame.height() + window_->menuBar()->sizeHint().height() + bar_->height();
}

void QtMainWindow::AdoptResolutionToWindowMonitor() {
    const auto& dc = emu_.Get<cerfcore::DeviceConfig>();
    if (!dc.guest_additions || !dc.adopt_guest_additions_resolution_for_host_screen) return;
    const QRect work = window_->screen()->availableGeometry();
    int         ex_w = 0, ex_h = 0;
    ChromeExtent(ex_w, ex_h);
    const qreal dpr    = window_->devicePixelRatioF();
    const int   surf_w = static_cast<int>((work.width() - ex_w) * dpr);
    const int   surf_h = static_cast<int>((work.height() - ex_h) * dpr);
    if (surf_w < 1 || surf_h < 1) return;
    emu_.Get<cerfcore::CerfVirtFramebuffer>().ApplyGuestMode(static_cast<uint32_t>(surf_w),
                                                             static_cast<uint32_t>(surf_h));
    initial_surface_w_ = static_cast<uint32_t>(surf_w);
    initial_surface_h_ = static_cast<uint32_t>(surf_h);
    SetGuestSurfaceSize(initial_surface_w_, initial_surface_h_);
    LOG(Lcd, "QtMainWindow: adopt fit monitor work=%dx%d -> guest surface %dx%d\n", work.width(),
        work.height(), surf_w, surf_h);
}

void QtMainWindow::FitWindowToSurface(uint32_t sw, uint32_t sh) {
    if (!window_ || sw == 0 || sh == 0 || fullscreen_) return;
    int ex_w = 0, ex_h = 0;
    ChromeExtent(ex_w, ex_h);
    const qreal dpr     = window_->devicePixelRatioF();
    const QSize frame   = window_->frameGeometry().size() - window_->geometry().size();
    const QRect work    = window_->screen()->availableGeometry();
    const int   outer_w = std::min(LogicalExtentCovering(static_cast<int>(sw), dpr) + ex_w, work.width());
    const int   outer_h = std::min(LogicalExtentCovering(static_cast<int>(sh), dpr) + ex_h, work.height());
    if (window_->isMaximized()) window_->showNormal();
    window_->ResizeTo(QSize(outer_w - frame.width(), outer_h - frame.height()));
    window_->move(work.left() + (work.width() - outer_w) / 2, work.top() + (work.height() - outer_h) / 2);
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
    auto* ar = emu_.TryGet<cerffrontend::GuestAutoResize>();
    if (ar && ar->Enabled() && !window_->isMinimized()) resize_debounce_->start();
}

void QtMainWindow::FireAutoResize() {
    const qreal dpr = canvas_->Dpr();
    if (auto* ar = emu_.TryGet<cerffrontend::GuestAutoResize>())
        ar->OnUserResizeEnd(static_cast<uint32_t>(DeviceExtent(canvas_->width(), dpr)),
                            static_cast<uint32_t>(DeviceExtent(canvas_->height(), dpr)));
}

void QtMainWindow::CloseRequested() {
    if (!emu_.Get<cerffrontend::ShutdownPrompt>().BeginCloseRequest()) return;
    RunOnUiThread([this] { RunShutdownPrompt(); });
}

void QtMainWindow::RunShutdownPrompt() {
    emu_.Get<cerffrontend::ShutdownPrompt>().FinishCloseRequest(
        emu_.Get<QtShutdownDialog>().Show(cerfcore::ShutdownTrigger::WindowClose));
}

void QtMainWindow::BeginShutdownTeardown() {
    if (emu_.Get<cerffrontend::ShutdownTeardown>().Begin()) teardown_timer_->start();
}

void QtMainWindow::PollTeardown() {
    switch (emu_.Get<cerffrontend::ShutdownTeardown>().Poll()) {
        case cerffrontend::ShutdownTeardown::Step::kWaiting:
            return;
        case cerffrontend::ShutdownTeardown::Step::kStopped:
            teardown_timer_->stop();
            QCoreApplication::exit(0);
            return;
        case cerffrontend::ShutdownTeardown::Step::kWedged:
            teardown_timer_->stop();
            cerfcore::Log::Close();
            cerfcore::host_platform::ExitProcessNow(cerfcore::CERF_FATAL_RUNTIME_ERROR);
    }
}
