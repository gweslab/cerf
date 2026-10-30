#pragma once

#include "frontend_window.h"

#include <cerfcore/core/instance_gate.h>

#include <QObject>
#include <QPointer>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

class QTimer;
class QtEmulatorView;

class QtEmulatorWindow : public cerffrontend::FrontendWindow {
public:
    using cerffrontend::FrontendWindow::FrontendWindow;
    ~QtEmulatorWindow() override;

    Tab      CurrentTab() const override;
    void     SetTab(Tab tab, bool user_initiated) override;
    void     SetGuestResolution(uint32_t w, uint32_t h) override;
    void     OnLcdEnabled() override;
    void     NotifyGuestRemoded(uint32_t w, uint32_t h) override;
    uint32_t GuestSurfaceWidth() const override { return surface_w_.load(std::memory_order_acquire); }
    uint32_t GuestSurfaceHeight() const override { return surface_h_.load(std::memory_order_acquire); }
    void     SetGuestSurfaceSize(uint32_t w, uint32_t h) override;
    void     RunOnUiThread(std::function<void()> job) override;
    void     RunOnUiThreadAfter(uint32_t delay_ms, std::function<void()> job) override;
    bool     CaptureGuestSurface(std::vector<uint32_t>& out, uint32_t& w, uint32_t& h) override;
    uint64_t NativeHandle() const override { return native_handle_.load(std::memory_order_acquire); }
    void     OnPresentationChanged() override;

    void CloseRequested();
    void BeginShutdownTeardown();

    virtual void OnTeardownWedged() = 0;

protected:
    void AttachView(QtEmulatorView& view, QObject& window);
    void PublishNativeHandle(uint64_t handle);
    void DetachView();
    bool AdoptsHostResolution() const;

    const cerfcore::InstanceGate gate_{emu_};

private:
    void ApplyPresentation();
    void Post(std::function<void()> job);
    void RunShutdownPrompt();
    void PollTeardown();

    std::mutex                         held_mutex_;
    std::vector<std::function<void()>> held_;
    bool                               attached_ = false;
    QtEmulatorView*                    view_     = nullptr;
    QPointer<QObject>                  context_;
    QObject                            jobs_;
    std::unique_ptr<QTimer>            teardown_timer_;
    std::shared_ptr<bool>              alive_ = std::make_shared<bool>(true);
    std::atomic<uint32_t>              surface_w_{0};
    std::atomic<uint32_t>              surface_h_{0};
    std::atomic<uint64_t>              native_handle_{0};
};
