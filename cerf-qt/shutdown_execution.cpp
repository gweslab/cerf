#include "shutdown_execution.h"

#include "host_power_actions.h"
#include "qt_emulator_window.h"

#include <cerfcore/boot/guest_cold_boot.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/socs/guest_cpu_reset.h>
#include <cerfcore/state/hibernation.h>

#include <utility>

namespace cerffrontend {

REGISTER_SERVICE(ShutdownExecution);

bool ShutdownExecution::Run(ShutdownAction action, std::function<void(bool saved)> save_done) {
    switch (action) {
        case ShutdownAction::Exit:
            emu_.Get<QtEmulatorWindow>().BeginShutdownTeardown();
            return true;
        case ShutdownAction::SoftReset:
            emu_.Get<cerfcore::GuestCpuReset>().WarmResetFromHost();
            return true;
        case ShutdownAction::HardReset:
            emu_.Get<cerfcore::GuestColdBoot>().RequestHardResetFromHost();
            return true;
        case ShutdownAction::SaveStateExit:
            return SaveAndExit(false, std::move(save_done));
        case ShutdownAction::SaveStateSuspendHost:
            emu_.Get<HostPowerActions>().RequireSuspend();
            return SaveAndExit(true, std::move(save_done));
        case ShutdownAction::SaveStatePoweroffHost: emu_.Get<HostPowerActions>().PowerOff();
        case ShutdownAction::SaveStateRestartHost:  emu_.Get<HostPowerActions>().Restart();
    }
    return false;
}

bool ShutdownExecution::SaveAndExit(bool suspend_host, std::function<void(bool saved)> save_done) {
    if (saving_) return false;
    saving_ = true;
    emu_.Get<cerfcore::Hibernation>().SaveAsync("", [this, suspend_host, save_done = std::move(save_done)](bool saved) {
        emu_.Get<QtEmulatorWindow>().RunOnUiThread([this, saved, suspend_host, save_done] {
            saving_ = false;
            save_done(saved);
            if (!saved) return;
            auto& window = emu_.Get<QtEmulatorWindow>();
            if (suspend_host) emu_.Get<HostPowerActions>().Suspend([&window] { window.BeginShutdownTeardown(); });
            else              window.BeginShutdownTeardown();
        });
    });
    return true;
}

}
