#include "qt_emulator_run.h"

#include "nested_event_loops.h"
#include "qt_emulator_window.h"
#include "qt_ui_thread_calls.h"
#include "shutdown_teardown.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/fatal.h>
#include <cerfcore/core/instance_threads.h>
#include <cerfcore/core/log.h>
#include <cerfcore/execution/jit_runner.h>

#include <QMetaObject>
#include <QTimer>

#include <chrono>
#include <utility>

QtEmulatorRun::QtEmulatorRun(const cerfcore::CerfConfig& cfg, int argc, char** argv, std::function<void()> on_exit,
                             std::function<void()> on_wedged)
    : args_(argv, argv + argc),
      argv_(PointersTo(args_)),
      emu_(std::make_unique<cerfcore::CerfEmulator>(cfg, argc, argv_.data())),
      on_exit_(std::move(on_exit)),
      on_wedged_(std::move(on_wedged)) {}

std::vector<char*> QtEmulatorRun::PointersTo(std::vector<std::string>& args) {
    std::vector<char*> pointers;
    for (std::string& arg : args) pointers.push_back(arg.data());
    pointers.push_back(nullptr);
    return pointers;
}

QtEmulatorRun::~QtEmulatorRun() { Stop(); }

void QtEmulatorRun::Boot() {
    const cerfcore::Log::CautionScope outside_instance(nullptr);
    emu_->CreateAllServices();
    cerfcore::Fatal& fatal = emu_->Get<cerfcore::Fatal>();
    {
        std::lock_guard<std::mutex> lock(window_mutex_);
        fatal_ = &fatal;
    }
    WatchStopAfterHalt(fatal);
    const auto booted = std::make_shared<bool>(false);
    boot_             = emu_->Get<cerfcore::InstanceThreads>().Start(
        [this, &fatal, booted] {
            {
                std::lock_guard<std::mutex> lock(window_mutex_);
                if (stopping_) return;
                ui_calls_ = &emu_->Get<QtUiThreadCalls>();
            }
            emu_->ResolveAllSlots();
            if (!RunWindowStep(fatal, [this] { emu_->Get<QtEmulatorWindow>().ShowWindow(); })) return;
            {
                std::lock_guard<std::mutex> lock(window_mutex_);
                window_open_ = true;
            }
            emu_->ReadyAllServices();
            if (!RunWindowStep(fatal, [this] { emu_->Get<QtEmulatorWindow>().AttachWindow(); })) return;
            {
                std::lock_guard<std::mutex> lock(window_mutex_);
                guest_started_ = true;
            }
            emu_->StartGuest();
            *booted = true;
        },
        [this, &fatal, booted] {
            if (*booted) {
                StartWaiter();
            } else if (fatal.Halted()) {
                PostExit();
            }
        });
    fatal.Guard([this] {
        auto& window = emu_->Get<QtEmulatorWindow>();
        window.SetWedgedHandler(std::move(on_wedged_));
        window.PrepareWindow();
    });
}

bool QtEmulatorRun::RunWindowStep(cerfcore::Fatal& fatal, std::function<void()> step) {
    {
        std::lock_guard<std::mutex> lock(window_mutex_);
        step_done_ = false;
    }
    QMetaObject::invokeMethod(
        &context_,
        [this, step = std::move(step), &fatal] {
            {
                std::lock_guard<std::mutex> lock(window_mutex_);
                if (stopping_) return;
            }
            const bool done = fatal.Guard([&step] { step(); });
            std::lock_guard<std::mutex> lock(window_mutex_);
            step_done_ = done;
            window_changed_.notify_all();
        },
        Qt::QueuedConnection);
    std::unique_lock<std::mutex> lock(window_mutex_);
    window_changed_.wait(lock, [this, &fatal] { return step_done_ || stopping_ || fatal.Halted(); });
    return step_done_;
}

cerfcore::CerfEmulator* QtEmulatorRun::OpenEmulator() {
    std::lock_guard<std::mutex> lock(window_mutex_);
    return window_open_ ? emu_.get() : nullptr;
}

std::optional<int> QtEmulatorRun::Halt() {
    std::lock_guard<std::mutex> lock(window_mutex_);
    if (!fatal_->Halted()) return std::nullopt;
    return fatal_->HaltCode();
}

std::string QtEmulatorRun::CrashLogPath() {
    std::lock_guard<std::mutex> lock(window_mutex_);
    return fatal_->CrashLogPath();
}

void QtEmulatorRun::StartWaiter() {
    cerfcore::CerfEmulator* emu = emu_.get();
    waiter_ = emu->Get<cerfcore::InstanceThreads>().Start([emu] { emu->WaitForExit(); }, [this] { PostExit(); });
}

void QtEmulatorRun::WatchStopAfterHalt(cerfcore::Fatal& fatal) {
    fatal.RegisterHaltListener([this](int) {
        QMetaObject::invokeMethod(
            &context_,
            [this] {
                QTimer::singleShot(std::chrono::milliseconds(cerffrontend::ShutdownTeardown::kGraceMs), &context_,
                                   [this] { CheckStoppedAfterHalt(); });
            },
            Qt::QueuedConnection);
    });
}

void QtEmulatorRun::CheckStoppedAfterHalt() {
    {
        std::lock_guard<std::mutex> lock(window_mutex_);
        if (!guest_started_ || abandoned_) return;
    }
    if (!emu_ || emu_->Get<cerfcore::JitRunner>().Stopped()) return;
    const cerfcore::Log::CautionScope outside_instance(nullptr);
    LOG(Caution, "QtEmulatorRun: the guest did not stop within %ums of the halt\n",
        cerffrontend::ShutdownTeardown::kGraceMs);
    emu_->Get<QtEmulatorWindow>().OnTeardownWedged();
}

void QtEmulatorRun::PostExit() {
    QMetaObject::invokeMethod(
        &context_,
        [this] {
            {
                std::lock_guard<std::mutex> lock(window_mutex_);
                if (abandoned_) return;
            }
            if (cerfcore::CerfEmulator* emu = OpenEmulator()) {
                auto& loops = emu->Get<NestedEventLoops>();
                if (loops.Running()) {
                    loops.QuitAll([this] { PostExit(); });
                    return;
                }
            }
            on_exit_();
        },
        Qt::QueuedConnection);
}

void QtEmulatorRun::Abandon() {
    QtUiThreadCalls* calls = nullptr;
    {
        std::lock_guard<std::mutex> lock(window_mutex_);
        stopping_  = true;
        abandoned_ = true;
        calls      = ui_calls_;
        window_changed_.notify_all();
    }
    calls->Close();
}

void QtEmulatorRun::Stop() {
    if (!emu_) return;
    const cerfcore::Log::CautionScope outside_instance(nullptr);
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
