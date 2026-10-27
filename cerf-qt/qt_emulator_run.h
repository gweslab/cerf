#pragma once

#include <cerfcore/core/cerf_config.h>

#include <QObject>

#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

namespace cerfcore {
class CerfEmulator;
}

class QtUiThreadCalls;

class QtEmulatorRun {
public:
    QtEmulatorRun(const cerfcore::CerfConfig& cfg, int argc, char** argv, std::function<void()> on_exit);
    ~QtEmulatorRun();

    QtEmulatorRun(const QtEmulatorRun&)            = delete;
    QtEmulatorRun& operator=(const QtEmulatorRun&) = delete;

    void                    Boot();
    void                    BootInBackground(std::function<void(cerfcore::CerfEmulator&)> open_window);
    cerfcore::CerfEmulator* OpenEmulator();
    void                    Stop();

private:
    void StartWaiter();

    std::unique_ptr<cerfcore::CerfEmulator> emu_;
    std::function<void()>                   on_exit_;
    QObject                                 context_;
    std::thread                             boot_;
    std::thread                             waiter_;
    std::mutex                              window_mutex_;
    std::condition_variable                 window_changed_;
    QtUiThreadCalls*                        ui_calls_      = nullptr;
    bool                                    window_open_   = false;
    bool                                    guest_started_ = false;
    bool                                    stopping_      = false;
};
