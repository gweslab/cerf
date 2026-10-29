#pragma once

#include <cerfcore/core/cerf_config.h>

#include <QObject>

#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace cerfcore {
class CerfEmulator;
class Fatal;
}

class QtUiThreadCalls;

class QtEmulatorRun {
public:
    QtEmulatorRun(const cerfcore::CerfConfig& cfg, int argc, char** argv, std::function<void()> on_exit,
                  std::function<void(cerfcore::CerfEmulator&)> on_wedged);
    ~QtEmulatorRun();

    QtEmulatorRun(const QtEmulatorRun&)            = delete;
    QtEmulatorRun& operator=(const QtEmulatorRun&) = delete;

    bool                    Boot();
    void                    BootInBackground(std::function<void(cerfcore::CerfEmulator&)> open_window);
    cerfcore::CerfEmulator* OpenEmulator();
    std::optional<int>      Halt();
    std::string             CrashLogPath();
    void                    Stop();
    void                    Abandon();

private:
    static std::vector<char*> PointersTo(std::vector<std::string>& args);

    void StartWaiter();
    void PostExit();
    void WatchStopAfterHalt(cerfcore::Fatal& fatal);
    void CheckStoppedAfterHalt();

    std::vector<std::string>                     args_;
    std::vector<char*>                           argv_;
    std::unique_ptr<cerfcore::CerfEmulator>      emu_;
    std::function<void()>                        on_exit_;
    std::function<void(cerfcore::CerfEmulator&)> on_wedged_;
    QObject                                      context_;
    std::thread                                  boot_;
    std::thread                                  waiter_;
    std::mutex                                   window_mutex_;
    std::condition_variable                      window_changed_;
    cerfcore::Fatal*                             fatal_         = nullptr;
    QtUiThreadCalls*                             ui_calls_      = nullptr;
    bool                                         window_open_   = false;
    bool                                         guest_started_ = false;
    bool                                         stopping_      = false;
    bool                                         abandoned_     = false;
};
