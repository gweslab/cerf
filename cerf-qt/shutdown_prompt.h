#pragma once

#include <cerfcore/core/service.h>
#include <cerfcore/state/shutdown_choice.h>

#include <cstdint>
#include <string>

namespace cerffrontend {

enum class ShutdownPromptAction : int { Exit = 0, SoftReset = 1, HardReset = 2 };

class ShutdownPrompt : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static constexpr int      kActionCount = 3;
    static constexpr uint32_t kCountdownMs = 15000u;

    const char* Title() const;
    const char* Intro(cerfcore::ShutdownTrigger trigger) const;
    const char* Question() const;
    const char* ActionLabel(ShutdownPromptAction action) const;
    const char* ResetDescription(ShutdownPromptAction action) const;
    const char* CancelLabel(cerfcore::ShutdownTrigger trigger) const;
    const char* RememberLabel() const;
    const char* SaveTitle() const;
    std::string SaveDetail() const;
    std::string SaveLabel() const;
    const char* SaveLinkUrl() const;
    const char* SaveLinkText() const;
    const char* SaveTail() const;
    bool        CountsDown(cerfcore::ShutdownTrigger trigger) const;
    bool        SaveByDefault() const;

    cerfcore::ShutdownChoice Commit(ShutdownPromptAction action, bool save, bool remember);

    bool BeginCloseRequest();
    void FinishCloseRequest(cerfcore::ShutdownChoice choice);
    void CancelCloseRequest();

private:
    unsigned long long SaveMegabytes() const;

    bool close_pending_ = false;
};

}
