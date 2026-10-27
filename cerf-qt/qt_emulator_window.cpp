#include "qt_emulator_window.h"

#include "qt_emulator_view.h"

#include "canvas_tabs.h"
#include "shutdown_prompt.h"
#include "shutdown_teardown.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/log.h>
#include <cerfcore/host/frame_renderer.h>
#include <cerfcore/host/shutdown_host.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_framebuffer.h>
#include <cerfcore/platform/host_process.h>

#include <QCoreApplication>
#include <QMetaObject>
#include <QTimer>

QtEmulatorWindow::~QtEmulatorWindow() = default;

void QtEmulatorWindow::AttachView(QtEmulatorView& view, QObject& window) {
    view_    = &view;
    context_ = &window;
    view.SetFramebufferActive(CurrentTab() == Tab::Framebuffer);
    surface_w_.store(view.GuestSurfaceWidth(), std::memory_order_release);
    surface_h_.store(view.GuestSurfaceHeight(), std::memory_order_release);
    teardown_timer_ = std::make_unique<QTimer>();
    teardown_timer_->setInterval(static_cast<int>(cerffrontend::ShutdownTeardown::kPollMs));
    QObject::connect(teardown_timer_.get(), &QTimer::timeout, [this] { PollTeardown(); });
    std::lock_guard<std::mutex> lock(held_mutex_);
    attached_ = true;
    for (std::function<void()>& job : held_) Post(std::move(job));
    held_.clear();
}

void QtEmulatorWindow::PublishNativeHandle(uint64_t handle) {
    native_handle_.store(handle, std::memory_order_release);
}

void QtEmulatorWindow::DetachView() {
    *alive_ = false;
    if (teardown_timer_) teardown_timer_->stop();
    view_ = nullptr;
    native_handle_.store(0, std::memory_order_release);
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
    view_->SetFramebufferActive(tab == Tab::Framebuffer);
    view_->Repaint();
}

void QtEmulatorWindow::SetGuestSurfaceSize(uint32_t w, uint32_t h) {
    view_->SetGuestSurfaceSize(w, h);
    surface_w_.store(view_->GuestSurfaceWidth(), std::memory_order_release);
    surface_h_.store(view_->GuestSurfaceHeight(), std::memory_order_release);
}

void QtEmulatorWindow::SetGuestResolution(uint32_t w, uint32_t h) {
    if (w == 0 || h == 0) return;
    emu_.Get<cerfcore::CerfVirtFramebuffer>().ApplyGuestMode(w, h);
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

void QtEmulatorWindow::NotifyGuestRemoded(uint32_t w, uint32_t h) {
    RunOnUiThread([this, w, h] { SetGuestResolution(w, h); });
}

void QtEmulatorWindow::RunOnUiThread(std::function<void()> job) {
    std::lock_guard<std::mutex> lock(held_mutex_);
    if (!attached_) {
        held_.push_back(std::move(job));
        return;
    }
    Post(std::move(job));
}

void QtEmulatorWindow::Post(std::function<void()> job) {
    QMetaObject::invokeMethod(
        QCoreApplication::instance(),
        [alive = alive_, job = std::move(job)] {
            if (*alive) job();
        },
        Qt::QueuedConnection);
}

void QtEmulatorWindow::RunOnUiThreadAfter(uint32_t delay_ms, std::function<void()> job) {
    QTimer::singleShot(static_cast<int>(delay_ms), context_.data(), std::move(job));
}

bool QtEmulatorWindow::CaptureGuestSurface(std::vector<uint32_t>& out, uint32_t& w, uint32_t& h) {
    return view_->CaptureSurface(out, w, h);
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
            cerfcore::Log::Close();
            cerfcore::host_platform::ExitProcessNow(cerfcore::CERF_FATAL_RUNTIME_ERROR);
    }
}
