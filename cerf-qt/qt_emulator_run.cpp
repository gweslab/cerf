#include "qt_emulator_run.h"

#include "qt_ui_thread_calls.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/execution/jit_runner.h>

#include <QMetaObject>

#include <utility>

QtEmulatorRun::QtEmulatorRun(const cerfcore::CerfConfig& cfg, int argc, char** argv, std::function<void()> on_exit)
    : emu_(std::make_unique<cerfcore::CerfEmulator>(cfg, argc, argv)), on_exit_(std::move(on_exit)) {}

QtEmulatorRun::~QtEmulatorRun() { Stop(); }

void QtEmulatorRun::Boot() {
    emu_->Boot();
    {
        std::lock_guard<std::mutex> lock(window_mutex_);
        ui_calls_      = &emu_->Get<QtUiThreadCalls>();
        window_open_   = true;
        guest_started_ = true;
    }
    StartWaiter();
}

void QtEmulatorRun::BootInBackground(std::function<void(cerfcore::CerfEmulator&)> open_window) {
    emu_->CreateAllServices();
    boot_ = std::thread([this, open_window = std::move(open_window)] {
        {
            std::lock_guard<std::mutex> lock(window_mutex_);
            if (stopping_) return;
            ui_calls_ = &emu_->Get<QtUiThreadCalls>();
        }
        emu_->ResolveAllSlots();
        emu_->ReadyAllServices();
        QMetaObject::invokeMethod(
            &context_,
            [this, open_window] {
                {
                    std::lock_guard<std::mutex> lock(window_mutex_);
                    if (stopping_) return;
                }
                open_window(*emu_);
                std::lock_guard<std::mutex> lock(window_mutex_);
                window_open_ = true;
                window_changed_.notify_all();
            },
            Qt::QueuedConnection);
        {
            std::unique_lock<std::mutex> lock(window_mutex_);
            window_changed_.wait(lock, [this] { return window_open_ || stopping_; });
            if (!window_open_) return;
            guest_started_ = true;
        }
        emu_->StartGuest();
        StartWaiter();
    });
}

cerfcore::CerfEmulator* QtEmulatorRun::OpenEmulator() {
    std::lock_guard<std::mutex> lock(window_mutex_);
    return window_open_ ? emu_.get() : nullptr;
}

void QtEmulatorRun::StartWaiter() {
    cerfcore::CerfEmulator* emu = emu_.get();
    waiter_                     = std::thread([this, emu] {
        emu->WaitForExit();
        QMetaObject::invokeMethod(&context_, [this] { on_exit_(); }, Qt::QueuedConnection);
    });
}

void QtEmulatorRun::Stop() {
    if (!emu_) return;
    QtUiThreadCalls* calls = nullptr;
    {
        std::lock_guard<std::mutex> lock(window_mutex_);
        stopping_ = true;
        calls     = ui_calls_;
        window_changed_.notify_all();
    }
    if (calls) calls->Close();
    if (boot_.joinable()) boot_.join();
    if (guest_started_) {
        emu_->Get<cerfcore::JitRunner>().RequestStop();
        if (waiter_.joinable()) waiter_.join();
        emu_->WaitForExit();
    }
    emu_.reset();
}
