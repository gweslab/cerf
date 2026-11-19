#include "automation_params.h"
#include "automation_server.h"

#include "../automation_option.h"
#include "../frontend_window.h"
#include "../shutdown_execution.h"
#include "../shutdown_policy.h"
#include "../version.h"

#include <cerfcore/boards/board_context.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/product_name.h>
#include <cerfcore/core/service.h>
#include <cerfcore/host/emulation_pause.h>
#include <cerfcore/host/frame_renderer.h>
#include <cerfcore/host/guest_deep_sleep.h>
#include <cerfcore/host/host_pointer_input_lock.h>
#include <cerfcore/platform/host_process.h>
#include <cerfcore/state/hibernation.h>

#include <optional>
#include <string>

namespace cerffrontend {

namespace {

constexpr char kCannotPauseText[]   = "the emulator cannot pause now: the guest has not started, or a save or load runs";
constexpr char kNotSuspendedText[]  = "the guest is not suspended";
constexpr char kStateBusyText[]     = "a save or a load already runs";
constexpr char kNotSavedText[]      = "the state was not saved; see the log";

const char* OutcomeName(cerfcore::Hibernation::RestoreOutcome outcome) {
    switch (outcome) {
        case cerfcore::Hibernation::RestoreOutcome::Refused:            return "refused";
        case cerfcore::Hibernation::RestoreOutcome::Resumed:            return "resumed";
        case cerfcore::Hibernation::RestoreOutcome::MemoryOnly:         return "memory_only";
        case cerfcore::Hibernation::RestoreOutcome::MemoryAfterRefusal: return "memory_after_refusal";
    }
    return "";
}

class AutomationMachineCommands : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    bool ShouldRegister() override { return AutomationRequested(emu_.Argc(), emu_.Argv()); }

    void OnReady() override {
        auto& server = emu_.Get<AutomationServer>();
        server.AddMethod("hello", "Identifies the instance and the protocol.", {}, "object",
                         [this](const AutomationCall& call) { Hello(call); });
        server.AddMethod("status", "Gives the current state of the machine.", {}, "object",
                         [this](const AutomationCall& call) { Status(call); });
        server.AddMethod("machine.pause", "Pauses or resumes the emulator.",
                         {{"paused", "bool", true, "true pauses, false resumes"}}, "empty object",
                         [this](const AutomationCall& call) { Pause(call); });
        server.AddMethod("machine.wake", "Wakes a suspended guest.", {}, "empty object",
                         [this](const AutomationCall& call) { Wake(call); });
        server.AddMethod("shutdown.actions", "Lists the ids of the shutdown actions.", {}, "array of action ids",
                         [](const AutomationCall& call) { Actions(call); });
        server.AddMethod("shutdown.run",
                         "Runs a shutdown action. A save action replies after the save, then the instance exits.",
                         {{"action", "string", true, "an id from shutdown.actions"}}, "empty object",
                         [this](const AutomationCall& call) { RunShutdown(call); });
        const AutomationParam path{"path", "string", false,
                                   "image path, relative to the device folder; the default state image when absent"};
        server.AddMethod("state.save", "Saves the machine state.", {path}, "empty object",
                         [this](const AutomationCall& call) { Save(call); });
        server.AddMethod("state.load", "Loads a machine state and replies when the load ends.",
                         {path,
                          {"ram_only", "bool", false, "true loads the memory only, as a warm boot"}},
                         "{outcome: refused|resumed|memory_only|memory_after_refusal, reason}",
                         [this](const AutomationCall& call) { Load(call); });
    }

private:
    void Hello(const AutomationCall& call) {
        auto&       board  = emu_.Get<cerfcore::BoardContext>();
        const auto& config = emu_.Get<cerfcore::DeviceConfig>();
        call.Reply(AutomationJson{{"protocol", AutomationServer::kProtocolVersion},
                                  {"product", cerfcore::kProductName},
                                  {"version", CERF_VERSION_STR},
                                  {"build", CERF_VERSION_BUILD},
                                  {"pid", cerfcore::host_platform::CurrentProcessId()},
                                  {"address", emu_.Get<AutomationServer>().Address()},
                                  {"device", config.device_name},
                                  {"board", std::string(board.GetBoardId())},
                                  {"board_name", board.BoardName()},
                                  {"soc", board.SocName()},
                                  {"guest_additions", config.guest_additions}});
    }

    void Status(const AutomationCall& call) {
        auto& window = emu_.Get<FrontendWindow>();
        auto& pause  = emu_.Get<cerfcore::EmulationPause>();
        call.Reply(AutomationJson{
            {"suspended", emu_.Get<cerfcore::GuestDeepSleep>().Suspended()},
            {"paused", pause.IsPaused()},
            {"user_paused", pause.IsUserPaused()},
            {"can_pause", pause.UserCanToggle()},
            {"has_frame", emu_.Get<cerfcore::FrameRenderer>().HasFrame()},
            {"screen", {{"width", window.GuestSurfaceWidth()}, {"height", window.GuestSurfaceHeight()}}},
            {"pointer_locked", emu_.Get<cerfcore::HostPointerInputLock>().Held()}});
    }

    void Pause(const AutomationCall& call) {
        if (!emu_.Get<cerfcore::EmulationPause>().SetUserPaused(AutomationParams(call.Params()).Boolean("paused")))
            throw AutomationError(AutomationServer::kRefused, kCannotPauseText);
        call.Reply(AutomationJson::object());
    }

    void Wake(const AutomationCall& call) {
        auto& sleep = emu_.Get<cerfcore::GuestDeepSleep>();
        if (!sleep.Suspended()) throw AutomationError(AutomationServer::kRefused, kNotSuspendedText);
        sleep.Resume();
        call.Reply(AutomationJson::object());
    }

    static void Actions(const AutomationCall& call) {
        AutomationJson ids = AutomationJson::array();
        for (ShutdownAction action : ShutdownPolicy::AllActions()) ids.push_back(ShutdownPolicy::Id(action));
        call.Reply(std::move(ids));
    }

    void RunShutdown(const AutomationCall& call) {
        const std::string id = AutomationParams(call.Params()).String("action");
        for (ShutdownAction action : ShutdownPolicy::AllActions()) {
            if (id != ShutdownPolicy::Id(action)) continue;
            const bool saves = action == ShutdownAction::SaveStateExit || action == ShutdownAction::SaveStateSuspendHost;
            const bool started = emu_.Get<ShutdownExecution>().Run(action, [call](bool saved) {
                if (saved) call.Reply(AutomationJson::object());
                else       call.Fail(AutomationServer::kRefused, kNotSavedText);
            });
            if (!started) throw AutomationError(AutomationServer::kRefused, kStateBusyText);
            if (!saves) call.Reply(AutomationJson::object());
            return;
        }
        throw AutomationError(AutomationServer::kInvalidParams, "unknown shutdown action " + id);
    }

    std::string StatePath(const AutomationParams& params) {
        const std::optional<std::string> path = params.OptionalString("path");
        if (!path) return {};
        return cerfcore::ResolveDeviceFile(emu_.Get<cerfcore::DeviceConfig>().device_name, *path);
    }

    void Save(const AutomationCall& call) {
        emu_.Get<cerfcore::Hibernation>().SaveAsync(StatePath(AutomationParams(call.Params())), [call](bool saved) {
            if (saved) call.Reply(AutomationJson::object());
            else       call.Fail(AutomationServer::kRefused, kNotSavedText);
        });
    }

    void Load(const AutomationCall& call) {
        const AutomationParams params(call.Params());
        const bool             ram_only = params.OptionalBoolean("ram_only").value_or(false);
        const bool started = emu_.Get<cerfcore::Hibernation>().RestoreAsync(
            StatePath(params), ram_only, [call](const cerfcore::Hibernation::RestoreResult& result) {
                call.Reply(AutomationJson{{"outcome", OutcomeName(result.outcome)}, {"reason", result.reason}});
            });
        if (!started) throw AutomationError(AutomationServer::kRefused, kStateBusyText);
    }
};

}

REGISTER_SERVICE(AutomationMachineCommands);

}
