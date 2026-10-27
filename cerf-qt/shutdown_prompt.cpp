#include "shutdown_prompt.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/product_name.h>
#include <cerfcore/cpu/emulated_memory.h>
#include <cerfcore/state/shutdown_action.h>
#include "frontend_config.h"
#include "product_links.h"
#include "shutdown_teardown.h"
#include "version.h"

#include <cstdio>

namespace cerffrontend {

REGISTER_SERVICE(ShutdownPrompt);

const char* ShutdownPrompt::Title() const { return "Shut down - " CERF_PRODUCT_NAME; }

const char* ShutdownPrompt::Intro(cerfcore::ShutdownTrigger trigger) const {
    return trigger == cerfcore::ShutdownTrigger::DeepSleep
               ? "The guest OS has requested a shut down."
               : "You have requested a shut down.";
}

const char* ShutdownPrompt::Question() const {
    return "What do you want to do?";
}

const char* ShutdownPrompt::ActionLabel(ShutdownPromptAction action) const {
    static constexpr const char* kLabels[kActionCount] = {"Exit emulator", "Soft reset", "Hard reset"};
    return kLabels[static_cast<int>(action)];
}

const char* ShutdownPrompt::ResetDescription(ShutdownPromptAction action) const {
    if (action == ShutdownPromptAction::HardReset) {
        return "All guest RAM is wiped and the operating system starts with no earlier "
               "context, the same as a battery pull.\n\n"
               "Data that lives in persistent storage - flash, NAND or a disk image - is "
               "not touched.";
    }
    return "The guest operating system restarts and keeps everything in RAM, so the "
           "object store and any open data survive.\n\n"
           "A ROM that does not support a warm start can still clear that data itself.";
}

const char* ShutdownPrompt::CancelLabel(cerfcore::ShutdownTrigger trigger) const {
    return trigger == cerfcore::ShutdownTrigger::DeepSleep ? "Resume" : "Cancel";
}

const char* ShutdownPrompt::RememberLabel() const {
    return "Remember this choice";
}

const char* ShutdownPrompt::SaveTitle() const {
    return "Save the state";
}

unsigned long long ShutdownPrompt::SaveMegabytes() const {
    return emu_.Get<cerfcore::EmulatedMemory>().VolatileByteCount() >> 20;
}

std::string ShutdownPrompt::SaveDetail() const {
    char text[32];
    std::snprintf(text, sizeof(text), "%llu MB", SaveMegabytes());
    return text;
}

std::string ShutdownPrompt::SaveLabel() const {
    char text[64];
    std::snprintf(text, sizeof(text), "Save the state (%llu MB, ", SaveMegabytes());
    return text;
}

const char* ShutdownPrompt::SaveLinkUrl() const {
    return kHibernationWarningUrl.text;
}

const char* ShutdownPrompt::SaveLinkText() const {
    return "only for CERF " CERF_VERSION_LABEL;
}

const char* ShutdownPrompt::SaveTail() const {
    return ")";
}

bool ShutdownPrompt::CountsDown(cerfcore::ShutdownTrigger trigger) const {
    return trigger == cerfcore::ShutdownTrigger::WindowClose;
}

bool ShutdownPrompt::SaveByDefault() const {
    return emu_.Get<FrontendConfig>().LastSaveStateMode();
}

cerfcore::ShutdownChoice ShutdownPrompt::Commit(ShutdownPromptAction action, bool save,
                                                bool remember) {
    switch (action) {
        case ShutdownPromptAction::SoftReset: return cerfcore::ShutdownChoice::SoftReset;
        case ShutdownPromptAction::HardReset: return cerfcore::ShutdownChoice::HardReset;
        case ShutdownPromptAction::Exit:      break;
    }
    if (remember) emu_.Get<FrontendConfig>().SaveLastSaveStateMode(save);
    return save ? cerfcore::ShutdownChoice::ExitSave : cerfcore::ShutdownChoice::Exit;
}

bool ShutdownPrompt::BeginCloseRequest() {
    if (close_pending_ || emu_.Get<ShutdownTeardown>().Active()) return false;
    close_pending_ = true;
    return true;
}

void ShutdownPrompt::FinishCloseRequest(cerfcore::ShutdownChoice choice) {
    if (choice != cerfcore::ShutdownChoice::Exit && choice != cerfcore::ShutdownChoice::ExitSave)
        close_pending_ = false;
    emu_.Get<cerfcore::ShutdownAction>().Perform(choice);
}

void ShutdownPrompt::CancelCloseRequest() {
    close_pending_ = false;
}

}
