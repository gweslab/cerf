#pragma once

#include <cerfcore/core/service.h>

#include <chrono>
#include <functional>

namespace cerffrontend {

class KioskMode : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static constexpr int                       kExitTaps = 5;
    static constexpr std::chrono::milliseconds kTapGap{1000};

    void OnReady() override;

    bool Active() const { return active_; }
    void Enter();
    void NoteHostKeyTap();

    virtual void CloseRequested(std::function<void()> proceed) = 0;

protected:
    virtual void Lock()   = 0;
    virtual void Unlock() = 0;

private:
    void Exit();
    bool Store(bool on);

    bool                                  active_ = false;
    int                                   taps_   = 0;
    std::chrono::steady_clock::time_point last_tap_{};
};

}
