#include "automation_object_state.h"
#include "automation_params.h"
#include "automation_request_answers.h"
#include "automation_server.h"

#include "../automation_option.h"
#include "../host_holds_release.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/service.h>
#include <cerfcore/host/battery.h>
#include <cerfcore/host/keyboard_input.h>
#include <cerfcore/host/keyboard_router.h>
#include <cerfcore/host/machine_guest_calibration.h>
#include <cerfcore/host/machine_indicators.h>
#include <cerfcore/host/machine_object_tree.h>
#include <cerfcore/host/machine_phone_line.h>
#include <cerfcore/host/machine_pointer_feature.h>
#include <cerfcore/host/machine_power_input.h>
#include <cerfcore/host/machine_socket.h>
#include <cerfcore/host/machine_temperature_sensor.h>
#include <cerfcore/host/pointer_router.h>
#include <cerfcore/host/pointer_source.h>

#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace cerffrontend {

namespace {

const char* EventName(cerfcore::MachineEventKind kind) {
    switch (kind) {
        case cerfcore::MachineEventKind::kAdded:    return "added";
        case cerfcore::MachineEventKind::kChanged:  return "changed";
        case cerfcore::MachineEventKind::kInserted: return "inserted";
        case cerfcore::MachineEventKind::kEjected:  return "ejected";
        case cerfcore::MachineEventKind::kFailed:   return "failed";
    }
    return "";
}

const char* InsertRefusal(cerfcore::InsertStatus status) {
    switch (status) {
        case cerfcore::InsertStatus::kAccepted:        return "";
        case cerfcore::InsertStatus::kUnknownType:     return "the socket does not take that type";
        case cerfcore::InsertStatus::kUnknownCommand:  return "the type has no such command";
        case cerfcore::InsertStatus::kInvalidArgument: return "the command does not take that argument";
    }
    return "";
}

AutomationParam PathParam() { return {"path", "string[]", true, "the id path of the object, from objects.list"}; }

class AutomationObjectCommands : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    bool ShouldRegister() override { return AutomationRequested(emu_.Argc(), emu_.Argv()); }

    void OnReady() override {
        auto& server = emu_.Get<AutomationServer>();
        RegisterTree(server);
        RegisterSockets(server);
        RegisterLevers(server);
        object_topic_ = server.AddTopic("object", "A machine object changed, took or lost a card, or failed.");
        emu_.Get<cerfcore::MachineObjectTree>().Subscribe([this, &server](const cerfcore::MachineEvent& event) {
            server.Publish(object_topic_, [this, event] {
                return AutomationJson{{"event", EventName(event.kind)},
                                      {"object", emu_.Get<AutomationObjectState>().Of(*event.object)},
                                      {"reason", event.reason},
                                      {"code", event.code},
                                      {"subject", event.subject}};
            });
        });
    }

private:
    void RegisterTree(AutomationServer& server) {
        server.AddMethod("objects.list", "Lists every machine object of the device with its state.", {},
                         "array of objects", [this](const AutomationCall& call) { List(call); });
        server.AddMethod("objects.get", "Gives one machine object with its state.", {PathParam()}, "object",
                         [this](const AutomationCall& call) {
                             call.Reply(emu_.Get<AutomationObjectState>().Of(Find(call)));
                         });
    }

    void RegisterSockets(AutomationServer& server) {
        server.AddMethod(
            "socket.insert",
            "Inserts a card or a cable by a command of an accepted type. Each request of the command takes its "
            "answer from answers by request id. A request with no answer goes out as a request event.",
            {PathParam(),
             {"type", "string", true, "an accepted type id"},
             {"command", "string", true, "a command id of that type"},
             {"argument", "string", false, "an argument id of that command"},
             {"answers", "object", false, "request id -> answer (path string, string array or size)"}},
            "the request ids answered from answers, and the requests left waiting",
            [this](const AutomationCall& call) { Insert(call); });
        server.AddMethod("socket.eject", "Ejects the card or cable of a socket.", {PathParam()}, "empty object",
                         [this](const AutomationCall& call) {
                             As<cerfcore::MachineSocket>(call, "socket").Eject();
                             call.Reply(AutomationJson::object());
                         });
    }

    void RegisterLevers(AutomationServer& server) {
        server.AddMethod("button.press", "Presses a device button and holds it until button.release.", {PathParam()},
                         "empty object", [this](const AutomationCall& call) { HoldButton(call, true); });
        server.AddMethod("button.release", "Releases a device button that this connection pressed.", {PathParam()},
                         "empty object", [this](const AutomationCall& call) { HoldButton(call, false); });
        server.AddDisconnectListener([this](uint64_t connection) { ReleaseButtons(connection); });
        emu_.Get<HostHoldsRelease>().Add([this] {
            while (!held_buttons_.empty()) ReleaseButtons(held_buttons_.begin()->first);
        });
        server.AddMethod("feature.set", "Turns a pointer feature on or off.",
                         {PathParam(), {"enabled", "bool", true, "the new state"}}, "empty object",
                         [this](const AutomationCall& call) {
                             As<cerfcore::MachinePointerFeature>(call, "pointer feature")
                                 .SetEnabled(AutomationParams(call.Params()).Boolean("enabled"));
                             call.Reply(AutomationJson::object());
                         });
        server.AddMethod("power_input.set", "Sets the power-fail input.",
                         {PathParam(), {"failed", "bool", true, "true when the power fails"}}, "empty object",
                         [this](const AutomationCall& call) {
                             As<cerfcore::MachinePowerInput>(call, "power input")
                                 .SetPowerFailed(AutomationParams(call.Params()).Boolean("failed"));
                             call.Reply(AutomationJson::object());
                         });
        server.AddMethod("phone_line.set", "Plugs or unplugs the phone line.",
                         {PathParam(), {"plugged", "bool", true, "true when the line is plugged in"}}, "empty object",
                         [this](const AutomationCall& call) {
                             As<cerfcore::MachinePhoneLine>(call, "phone line")
                                 .SetPlugged(AutomationParams(call.Params()).Boolean("plugged"));
                             call.Reply(AutomationJson::object());
                         });
        server.AddMethod("battery.set", "Sets the charge and the external power of the battery.",
                         {PathParam(),
                          {"charge_percent", "int", false, "from 0 to 100"},
                          {"on_battery", "bool", false, "true when no external power is connected"}},
                         "empty object", [this](const AutomationCall& call) { SetBattery(call); });
        server.AddMethod("temperature.set", "Sets the reading of a temperature sensor.",
                         {PathParam(),
                          {"reported", "bool", true, "false stops the reports"},
                          {"half_celsius", "int", false, "the reading in half degrees Celsius; absent for no reading"}},
                         "empty object", [this](const AutomationCall& call) { SetTemperature(call); });
        server.AddMethod("calibration.use_stock_pointer",
                         "Switches the active pointer to the stock touch input for the calibration of the guest.",
                         {PathParam()}, "empty object", [this](const AutomationCall& call) {
                             As<cerfcore::MachineGuestCalibration>(call, "guest calibration").SwitchToStockPointer();
                             call.Reply(AutomationJson::object());
                         });
        server.AddMethod("source.set", "Selects the active pointer or keyboard source.",
                         {PathParam(), {"source", "string", true, "a source id from the state of the object"}},
                         "empty object", [this](const AutomationCall& call) { SetSource(call); });
    }

    cerfcore::MachineObject& Find(const AutomationCall& call) {
        cerfcore::MachineObject* object =
            emu_.Get<cerfcore::MachineObjectTree>().Find(AutomationParams(call.Params()).Strings("path"));
        if (object == nullptr) throw AutomationError(AutomationServer::kInvalidParams, "no object has that path");
        return *object;
    }

    template <class T>
    T& As(const AutomationCall& call, const char* kind) {
        auto* object = dynamic_cast<T*>(&Find(call));
        if (object == nullptr)
            throw AutomationError(AutomationServer::kInvalidParams, std::string("the object is not a ") + kind);
        return *object;
    }

    void HoldButton(const AutomationCall& call, bool down) {
        auto& button = As<cerfcore::MachineButton>(call, "button");
        auto& held   = held_buttons_[call.Connection()];
        if (down) {
            if (!held.insert(&button).second)
                throw AutomationError(AutomationServer::kRefused, "this connection already holds that button");
            button.Down();
        } else {
            if (held.erase(&button) == 0)
                throw AutomationError(AutomationServer::kRefused, "this connection does not hold that button");
            button.Up();
        }
        call.Reply(AutomationJson::object());
    }

    void ReleaseButtons(uint64_t connection) {
        const auto it = held_buttons_.find(connection);
        if (it == held_buttons_.end()) return;
        const std::set<cerfcore::MachineButton*> buttons = std::move(it->second);
        held_buttons_.erase(it);
        for (cerfcore::MachineButton* button : buttons) button->Up();
    }

    void Append(cerfcore::MachineObject* parent, AutomationJson& out) {
        auto& tree = emu_.Get<cerfcore::MachineObjectTree>();
        for (cerfcore::MachineObject* object : parent == nullptr ? tree.Roots() : tree.Children(parent)) {
            out.push_back(emu_.Get<AutomationObjectState>().Of(*object));
            Append(object, out);
        }
    }

    void List(const AutomationCall& call) {
        AutomationJson out = AutomationJson::array();
        Append(nullptr, out);
        call.Reply(std::move(out));
    }

    void Insert(const AutomationCall& call) {
        const AutomationParams params(call.Params());
        auto&                  socket   = As<cerfcore::MachineSocket>(call, "socket");
        const std::string      type     = params.String("type");
        const std::string      command  = params.String("command");
        const std::string      argument = params.OptionalString("argument").value_or("");
        const AutomationJson*  answers  = params.Find("answers");
        if (answers != nullptr && !answers->is_object())
            throw AutomationError(AutomationServer::kInvalidParams, "answers must be an object");
        AutomationRequestAnswers::Scope scope(emu_.Get<AutomationRequestAnswers>(), socket,
                                              answers ? *answers : AutomationJson::object());
        const cerfcore::InsertStatus    status = socket.Insert(type, command, argument);
        if (status != cerfcore::InsertStatus::kAccepted)
            throw AutomationError(AutomationServer::kRefused, InsertRefusal(status));
        call.Reply(scope.Report());
    }

    void SetBattery(const AutomationCall& call) {
        const AutomationParams params(call.Params());
        auto&                  battery = As<cerfcore::Battery>(call, "battery");
        const std::optional<int64_t> percent = params.OptionalInteger("charge_percent");
        const std::optional<bool>    on_battery = params.OptionalBoolean("on_battery");
        if (percent && (*percent < 0 || *percent > cerfcore::Battery::kFullPercent))
            throw AutomationError(AutomationServer::kInvalidParams, "charge_percent must be from 0 to 100");
        if (percent) battery.SetChargePercent(static_cast<int>(*percent));
        if (on_battery) battery.SetOnBattery(*on_battery);
        call.Reply(AutomationJson::object());
    }

    void SetTemperature(const AutomationCall& call) {
        const AutomationParams       params(call.Params());
        auto&                        sensor = As<cerfcore::MachineTemperatureSensor>(call, "temperature sensor");
        const std::optional<int64_t> half   = params.OptionalInteger("half_celsius");
        if (half && (*half < std::numeric_limits<int16_t>::min() || *half > std::numeric_limits<int16_t>::max()))
            throw AutomationError(AutomationServer::kInvalidParams, "half_celsius is out of range");
        cerfcore::TemperatureReading reading;
        reading.reported = params.Boolean("reported");
        if (half) reading.half_celsius = static_cast<int16_t>(*half);
        sensor.SetReading(reading);
        call.Reply(AutomationJson::object());
    }

    void SetSource(const AutomationCall& call) {
        const std::string        id     = AutomationParams(call.Params()).String("source");
        cerfcore::MachineObject& object = Find(call);
        if (auto* pointer = dynamic_cast<cerfcore::PointerRouter*>(&object)) {
            for (cerfcore::PointerSource* source : pointer->Sources())
                if (source->SourceId() == id) {
                    pointer->SetActive(source);
                    call.Reply(AutomationJson::object());
                    return;
                }
        } else if (auto* keyboard = dynamic_cast<cerfcore::KeyboardRouter*>(&object)) {
            for (cerfcore::KeyboardInput* source : keyboard->Sources())
                if (source->SourceId() == id) {
                    keyboard->SetActive(source);
                    call.Reply(AutomationJson::object());
                    return;
                }
        } else {
            throw AutomationError(AutomationServer::kInvalidParams, "the object is not a pointer or keyboard");
        }
        throw AutomationError(AutomationServer::kInvalidParams, "the object has no source with that id");
    }

    size_t                                                  object_topic_ = 0;
    std::map<uint64_t, std::set<cerfcore::MachineButton*>> held_buttons_;
};

}

REGISTER_SERVICE(AutomationObjectCommands);

}
