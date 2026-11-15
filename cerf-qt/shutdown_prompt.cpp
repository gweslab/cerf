#include "shutdown_prompt.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/product_name.h>
#include <cerfcore/cpu/emulated_memory.h>
#include <cerfcore/host/battery.h>
#include <cerfcore/host/guest_deep_sleep.h>
#include <cerfcore/host/machine_object_tree.h>
#include "frontend_config.h"
#include "product_links.h"
#include "shutdown_teardown.h"

#include <cstdio>

namespace cerffrontend {

REGISTER_SERVICE(ShutdownPrompt);

const char* ShutdownPrompt::Title() const { return "Shut down - " CERF_PRODUCT_NAME; }

const char* ShutdownPrompt::Heading() const { return "Shut down"; }

const char* ShutdownPrompt::Intro(ShutdownTrigger trigger) const {
    return trigger == ShutdownTrigger::GuestSleep
               ? "The guest OS has requested a shut down."
               : "You have requested a shut down.";
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

const char* ShutdownPrompt::CancelLabel(ShutdownTrigger trigger) const {
    return trigger == ShutdownTrigger::GuestSleep ? "Resume" : "Cancel";
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

const char* ShutdownPrompt::SaveLinkUrl() const {
    return kHibernationWarningUrl.text;
}

const char* ShutdownPrompt::SaveLinkText() const {
    return "data might be lost";
}

bool ShutdownPrompt::CountsDown(ShutdownTrigger trigger) const {
    return trigger == ShutdownTrigger::WindowClose && !emu_.Get<cerfcore::GuestDeepSleep>().Asleep();
}

bool ShutdownPrompt::SaveByDefault() const {
    return emu_.Get<FrontendConfig>().LastSaveStateMode();
}

const char* ShutdownPrompt::PlugInAcQuestion() const { return "Plug in AC?"; }

const char* ShutdownPrompt::PlugInAcReason() const {
    return "A guest OS might deadlock in sleep if the battery is low.";
}

std::function<void()> ShutdownPrompt::AcOffer(ShutdownTrigger trigger, ShutdownChoice choice) {
    const bool resumes = trigger == ShutdownTrigger::GuestSleep && choice == ShutdownChoice::Cancel;
    const bool resets  = choice == ShutdownChoice::SoftReset || choice == ShutdownChoice::HardReset;
    if (!resumes && !resets) return {};
    for (cerfcore::MachineObject* object : emu_.Get<cerfcore::MachineObjectTree>().Roots()) {
        auto* battery = dynamic_cast<cerfcore::Battery*>(object);
        if (battery != nullptr && battery->OnBattery()) return [battery] { battery->SetOnBattery(false); };
    }
    return {};
}

ShutdownChoice ShutdownPrompt::Commit(ShutdownPromptAction action, bool save, bool remember) {
    switch (action) {
        case ShutdownPromptAction::SoftReset: return ShutdownChoice::SoftReset;
        case ShutdownPromptAction::HardReset: return ShutdownChoice::HardReset;
        case ShutdownPromptAction::Exit:      break;
    }
    if (remember) emu_.Get<FrontendConfig>().SaveLastSaveStateMode(save);
    return save ? ShutdownChoice::ExitSave : ShutdownChoice::Exit;
}

bool ShutdownPrompt::BeginCloseRequest() {
    if (close_pending_ || emu_.Get<ShutdownTeardown>().Active()) return false;
    close_pending_ = true;
    return true;
}

void ShutdownPrompt::FinishCloseRequest(ShutdownChoice choice) {
    if (choice != ShutdownChoice::Exit && choice != ShutdownChoice::ExitSave) close_pending_ = false;
}

void ShutdownPrompt::CancelCloseRequest() {
    close_pending_ = false;
}

}
