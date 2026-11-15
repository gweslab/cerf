#pragma once

#include <cerfcore/core/service.h>

#include <cstdint>
#include <functional>
#include <string>

namespace cerffrontend {

enum class ShutdownPromptAction : int { Exit = 0, SoftReset = 1, HardReset = 2 };
enum class ShutdownTrigger { WindowClose, GuestSleep };
enum class ShutdownChoice { Cancel, Exit, ExitSave, SoftReset, HardReset };

class ShutdownPrompt : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static constexpr int      kActionCount = 3;
    static constexpr uint32_t kCountdownMs = 15000u;

    const char* Title() const;
    const char* Heading() const;
    const char* Intro(ShutdownTrigger trigger) const;
    const char* ActionLabel(ShutdownPromptAction action) const;
    const char* ResetDescription(ShutdownPromptAction action) const;
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

    ShutdownChoice Commit(ShutdownPromptAction action, bool save, bool remember);

    std::function<void()> AcOffer(ShutdownTrigger trigger, ShutdownChoice choice);

    bool BeginCloseRequest();
    void FinishCloseRequest(ShutdownChoice choice);
    void CancelCloseRequest();

private:
    unsigned long long SaveMegabytes() const;

    bool close_pending_ = false;
};

}
