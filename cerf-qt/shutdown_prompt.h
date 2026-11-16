#pragma once

#include "shutdown_policy.h"

#include <cerfcore/core/service.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace cerffrontend {

enum class ShutdownTrigger { WindowClose, GuestSleep };
enum class ShutdownChoice {
    Cancel,
    Exit,
    ExitSave,
    SoftReset,
    HardReset,
    SaveSuspendHost,
    SavePoweroffHost,
    SaveRestartHost,
};

class ShutdownPrompt : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static constexpr uint32_t kCountdownMs = 15000u;

    static bool Exits(ShutdownChoice choice);

    const char* Title() const;
    const char* Heading() const;
    const char* Intro(ShutdownTrigger trigger) const;
    const char* ActionLabel(ShutdownAction action) const;
    const char* ActionDescription(ShutdownAction action) const;
    const char* CancelLabel(ShutdownTrigger trigger) const;
    const char* RememberLabel() const;
    const char* SaveTitle() const;
    std::string SaveDetail() const;
    const char* SaveLinkUrl() const;
    const char* SaveLinkText() const;
    bool        CountsDown(ShutdownTrigger trigger) const;
    bool        SaveByDefault() const;
    const char* PlugInAcQuestion() const;
    const char* PlugInAcReason() const;

    std::vector<ShutdownAction> Actions() const;
    bool                        Unattended() const;

    ShutdownChoice Commit(ShutdownAction action, bool save, bool remember);
    ShutdownChoice CommitUnattended();

    std::function<void()> AcOffer(ShutdownTrigger trigger, ShutdownChoice choice);

    bool BeginCloseRequest();
    void FinishCloseRequest(ShutdownChoice choice);
    void CancelCloseRequest();

private:
    unsigned long long SaveMegabytes() const;

    bool close_pending_ = false;
};

}
