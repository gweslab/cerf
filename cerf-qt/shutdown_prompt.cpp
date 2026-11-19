#include "shutdown_prompt.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/product_name.h>
#include <cerfcore/cpu/emulated_memory.h>
#include <cerfcore/host/battery.h>
#include <cerfcore/host/guest_deep_sleep.h>
#include <cerfcore/host/machine_object_tree.h>
#include "enterprise_config.h"
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

const char* ShutdownPrompt::ActionLabel(ShutdownAction action) const {
    switch (action) {
        case ShutdownAction::Exit:                  return "Exit emulator";
        case ShutdownAction::SoftReset:             return "Soft reset";
        case ShutdownAction::HardReset:             return "Hard reset";
        case ShutdownAction::SaveStateExit:         return "Save state and exit";
        case ShutdownAction::SaveStateSuspendHost:  return "Save state and suspend host";
        case ShutdownAction::SaveStatePoweroffHost: return "Save state and power off host";
        case ShutdownAction::SaveStateRestartHost:  return "Save state and restart host";
    }
    return "";
}

const char* ShutdownPrompt::ActionDescription(ShutdownAction action) const {
    switch (action) {
        case ShutdownAction::Exit: return "";
        case ShutdownAction::SoftReset:
            return "The guest operating system restarts and keeps everything in RAM, so the "
                   "object store and any open data survive.\n\n"
                   "A ROM that does not support a warm start can still clear that data itself.";
        case ShutdownAction::HardReset:
            return "All guest RAM is wiped and the operating system starts with no earlier "
                   "context, the same as a battery pull.\n\n"
                   "Data that lives in persistent storage - flash, NAND or a disk image - is "
                   "not touched.";
        case ShutdownAction::SaveStateExit: return "The emulator saves the state and exits.";
        case ShutdownAction::SaveStateSuspendHost:
            return "The emulator saves the state and exits. Then this computer goes to sleep.";
        case ShutdownAction::SaveStatePoweroffHost:
            return "The emulator saves the state and exits. Then this computer powers off.";
        case ShutdownAction::SaveStateRestartHost:
            return "The emulator saves the state and exits. Then this computer restarts.";
    }
    return "";
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
    return trigger == ShutdownTrigger::WindowClose && !emu_.Get<cerfcore::GuestDeepSleep>().Suspended() &&
           Actions().front() == ShutdownAction::Exit;
}

std::vector<ShutdownAction> ShutdownPrompt::Actions() const { return emu_.Get<ShutdownPolicy>().Actions(); }

bool ShutdownPrompt::Unattended() const {
    return emu_.Get<EnterpriseConfig>().Enabled() && Actions().size() == 1;
}

bool ShutdownPrompt::Exits(ShutdownChoice choice) {
    return choice == ShutdownChoice::Exit || choice == ShutdownChoice::ExitSave ||
           choice == ShutdownChoice::SaveSuspendHost;
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

ShutdownChoice ShutdownPrompt::Commit(ShutdownAction action, bool save, bool remember) {
    switch (action) {
        case ShutdownAction::SoftReset:             return ShutdownChoice::SoftReset;
        case ShutdownAction::HardReset:             return ShutdownChoice::HardReset;
        case ShutdownAction::SaveStateExit:         return ShutdownChoice::ExitSave;
        case ShutdownAction::SaveStateSuspendHost:  return ShutdownChoice::SaveSuspendHost;
        case ShutdownAction::SaveStatePoweroffHost: return ShutdownChoice::SavePoweroffHost;
        case ShutdownAction::SaveStateRestartHost:  return ShutdownChoice::SaveRestartHost;
        case ShutdownAction::Exit:                  break;
    }
    if (remember) emu_.Get<FrontendConfig>().SaveLastSaveStateMode(save);
    return save ? ShutdownChoice::ExitSave : ShutdownChoice::Exit;
}

ShutdownChoice ShutdownPrompt::CommitUnattended() { return Commit(Actions().front(), false, false); }

bool ShutdownPrompt::BeginCloseRequest() {
    if (close_pending_ || emu_.Get<ShutdownTeardown>().Active()) return false;
    close_pending_ = true;
    return true;
}

void ShutdownPrompt::FinishCloseRequest(ShutdownChoice choice) {
    if (!Exits(choice)) close_pending_ = false;
}

void ShutdownPrompt::CancelCloseRequest() {
    close_pending_ = false;
}

}
