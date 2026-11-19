#include "automation_object_state.h"

#include "../automation_option.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/folder_share_config.h>
#include <cerfcore/core/utf16.h>
#include <cerfcore/host/battery.h>
#include <cerfcore/host/keyboard_input.h>
#include <cerfcore/host/keyboard_router.h>
#include <cerfcore/host/machine_diagnostics_channel.h>
#include <cerfcore/host/machine_guest_calibration.h>
#include <cerfcore/host/machine_indicators.h>
#include <cerfcore/host/machine_object_tree.h>
#include <cerfcore/host/machine_phone_line.h>
#include <cerfcore/host/machine_pointer_feature.h>
#include <cerfcore/host/machine_power_input.h>
#include <cerfcore/host/machine_socket.h>
#include <cerfcore/host/machine_storage.h>
#include <cerfcore/host/machine_temperature_sensor.h>
#include <cerfcore/host/pointer_router.h>
#include <cerfcore/host/pointer_source.h>

#include <cstdio>
#include <string>
#include <type_traits>
#include <variant>

namespace cerffrontend {

REGISTER_SERVICE(AutomationObjectState);

namespace {

using cerfcore::MachineObjectKind;

AutomationJson Rgb(const cerfcore::ObjectRgb& rgb) { return AutomationJson{{"r", rgb.r}, {"g", rgb.g}, {"b", rgb.b}}; }

const char* PointerKindName(cerfcore::PointerKind kind) {
    switch (kind) {
        case cerfcore::PointerKind::Absolute: return "absolute";
        case cerfcore::PointerKind::Relative: return "relative";
        case cerfcore::PointerKind::Stylus:   return "stylus";
    }
    return "";
}

const char* MediumName(cerfcore::StorageMedium medium) {
    switch (medium) {
        case cerfcore::StorageMedium::kNorFlash:  return "nor_flash";
        case cerfcore::StorageMedium::kNandFlash: return "nand_flash";
        case cerfcore::StorageMedium::kHardDisk:  return "hard_disk";
    }
    return "";
}

AutomationJson FactsJson(const cerfcore::CardFacts& facts) {
    return std::visit(
        [](const auto& f) -> AutomationJson {
            using T = std::decay_t<decltype(f)>;
            if constexpr (std::is_same_v<T, cerfcore::StorageCardFacts>) {
                return AutomationJson{{"image_path", f.image_path}, {"capacity_bytes", f.capacity_bytes}};
            } else if constexpr (std::is_same_v<T, cerfcore::NetworkCardFacts>) {
                char mac[18];
                std::snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x", f.mac[0], f.mac[1], f.mac[2],
                              f.mac[3], f.mac[4], f.mac[5]);
                return AutomationJson{{"mac", mac}};
            } else if constexpr (std::is_same_v<T, cerfcore::SerialLinkFacts>) {
                return AutomationJson{{"host_port", f.host_port}};
            } else {
                return AutomationJson();
            }
        },
        facts);
}

}

bool AutomationObjectState::ShouldRegister() { return AutomationRequested(emu_.Argc(), emu_.Argv()); }

const char* AutomationObjectState::KindName(MachineObjectKind kind) {
    switch (kind) {
        case MachineObjectKind::kPcCardSocket:       return "pc_card_socket";
        case MachineObjectKind::kSerialPort:         return "serial_port";
        case MachineObjectKind::kStorage:            return "storage";
        case MachineObjectKind::kAudio:              return "audio";
        case MachineObjectKind::kPhoneLine:          return "phone_line";
        case MachineObjectKind::kBattery:            return "battery";
        case MachineObjectKind::kPowerInput:         return "power_input";
        case MachineObjectKind::kLamp:               return "lamp";
        case MachineObjectKind::kVibrator:           return "vibrator";
        case MachineObjectKind::kCharacterDisplay:   return "character_display";
        case MachineObjectKind::kButton:             return "button";
        case MachineObjectKind::kKeyboard:           return "keyboard";
        case MachineObjectKind::kPointer:            return "pointer";
        case MachineObjectKind::kPointerFeature:     return "pointer_feature";
        case MachineObjectKind::kSharedFolder:       return "shared_folder";
        case MachineObjectKind::kGuestAdditions:     return "guest_additions";
        case MachineObjectKind::kUsbFlasher:         return "usb_flasher";
        case MachineObjectKind::kMediaSocket:        return "media_socket";
        case MachineObjectKind::kCar:                return "car";
        case MachineObjectKind::kVehicleController:  return "vehicle_controller";
        case MachineObjectKind::kTemperatureSensor:  return "temperature_sensor";
        case MachineObjectKind::kDiagnosticsChannel: return "diagnostics_channel";
        case MachineObjectKind::kGuestCalibration:   return "guest_calibration";
    }
    return "";
}

AutomationJson AutomationObjectState::PathJson(cerfcore::MachineObject& object) {
    AutomationJson path = AutomationJson::array();
    for (const std::string& id : emu_.Get<cerfcore::MachineObjectTree>().PathOf(&object)) path.push_back(id);
    return path;
}

AutomationJson AutomationObjectState::Of(cerfcore::MachineObject& object) {
    return AutomationJson{{"path", PathJson(object)},
                          {"id", object.ObjectId()},
                          {"name", object.ObjectName()},
                          {"kind", KindName(object.ObjectKind())},
                          {"rx", object.RxCount()},
                          {"tx", object.TxCount()},
                          {"state", State(object)}};
}

AutomationJson AutomationObjectState::State(cerfcore::MachineObject& object) {
    if (dynamic_cast<cerfcore::MachineSocket*>(&object)) return SocketState(object);
    if (auto* storage = dynamic_cast<cerfcore::MachineStorage*>(&object))
        return AutomationJson{{"medium", MediumName(storage->Medium())}, {"image_path", storage->ImagePath()}};
    if (auto* power = dynamic_cast<cerfcore::MachinePowerInput*>(&object))
        return AutomationJson{{"power_failed", power->PowerFailed()}};
    if (auto* line = dynamic_cast<cerfcore::MachinePhoneLine*>(&object))
        return AutomationJson{{"plugged", line->Plugged()}};
    if (auto* battery = dynamic_cast<cerfcore::Battery*>(&object))
        return AutomationJson{{"charge_percent", battery->ChargePercent()},
                              {"on_battery", battery->OnBattery()},
                              {"on_external_power", battery->OnExternalPower()},
                              {"charging", battery->Charging()}};
    if (auto* feature = dynamic_cast<cerfcore::MachinePointerFeature*>(&object))
        return AutomationJson{{"available", feature->Available()}, {"enabled", feature->Enabled()}};
    if (auto* sensor = dynamic_cast<cerfcore::MachineTemperatureSensor*>(&object)) {
        const cerfcore::TemperatureReading reading = sensor->Reading();
        return AutomationJson{{"reported", reading.reported},
                              {"half_celsius", reading.half_celsius ? AutomationJson(*reading.half_celsius)
                                                                    : AutomationJson()}};
    }
    if (auto* channel = dynamic_cast<cerfcore::MachineDiagnosticsChannel*>(&object)) {
        const cerfcore::ChannelCounters counters = channel->Counters();
        AutomationJson                  signals  = AutomationJson::array();
        for (const cerfcore::ChannelSignal& s : channel->Signals())
            signals.push_back(AutomationJson{{"id", s.id}, {"reported", s.reported}, {"value", s.value}});
        return AutomationJson{{"counters",
                               {{"received", counters.received},
                                {"sent", counters.sent},
                                {"accepted", counters.accepted},
                                {"unsupported", counters.unsupported},
                                {"invalid", counters.invalid},
                                {"unavailable", counters.unavailable},
                                {"malformed", counters.malformed}}},
                              {"signals", std::move(signals)}};
    }
    if (auto* calibration = dynamic_cast<cerfcore::MachineGuestCalibration*>(&object))
        return AutomationJson{{"shown", calibration->Shown()}};
    if (auto* folder = dynamic_cast<cerfcore::FolderShareConfig*>(&object))
        return AutomationJson{{"enabled", folder->Enabled()},
                              {"host_root", folder->HostRoot()},
                              {"mount_point", cerfcore::Utf16ToUtf8(folder->MountPoint())}};
    if (dynamic_cast<cerfcore::PointerRouter*>(&object) || dynamic_cast<cerfcore::KeyboardRouter*>(&object))
        return InputSourceState(object);
    return IndicatorState(object);
}

AutomationJson AutomationObjectState::SocketState(cerfcore::MachineObject& object) {
    auto&          socket   = dynamic_cast<cerfcore::MachineSocket&>(object);
    AutomationJson accepted = AutomationJson::array();
    for (const cerfcore::InsertableType& type : socket.Accepted()) {
        AutomationJson commands = AutomationJson::array();
        for (const cerfcore::InsertCommand& command : type.commands) {
            AutomationJson arguments = AutomationJson::array();
            for (const cerfcore::InsertArgument& argument : command.arguments)
                arguments.push_back(AutomationJson{{"id", argument.id}, {"name", argument.name}});
            commands.push_back(AutomationJson{{"id", command.id}, {"arguments", std::move(arguments)}});
        }
        accepted.push_back(AutomationJson{{"id", type.id}, {"name", type.name}, {"commands", std::move(commands)}});
    }
    AutomationJson inserted;
    if (const std::optional<cerfcore::InsertedItem> item = socket.Inserted())
        inserted = AutomationJson{{"type", item->type_id}, {"name", item->name}, {"facts", FactsJson(item->facts)}};
    return AutomationJson{{"inserted", std::move(inserted)}, {"accepted", std::move(accepted)}};
}

AutomationJson AutomationObjectState::IndicatorState(cerfcore::MachineObject& object) {
    if (auto* lamp = dynamic_cast<cerfcore::MachineLamp*>(&object)) {
        const cerfcore::LampState state = lamp->Lamp();
        return AutomationJson{{"lit", state.lit},
                              {"blinking", state.blinking},
                              {"color", Rgb(state.color)},
                              {"blink_on_ms", state.blink_on_ms},
                              {"blink_off_ms", state.blink_off_ms},
                              {"between_blinks", state.between_blinks ? Rgb(*state.between_blinks) : AutomationJson()}};
    }
    if (auto* vibrator = dynamic_cast<cerfcore::MachineVibrator*>(&object))
        return AutomationJson{{"vibrating", vibrator->Vibrating()}};
    if (auto* display = dynamic_cast<cerfcore::MachineCharacterDisplay*>(&object))
        return AutomationJson{{"characters", display->Characters()}};
    return AutomationJson::object();
}

AutomationJson AutomationObjectState::InputSourceState(cerfcore::MachineObject& object) {
    AutomationJson sources = AutomationJson::array();
    AutomationJson active;
    if (auto* pointer = dynamic_cast<cerfcore::PointerRouter*>(&object)) {
        for (cerfcore::PointerSource* source : pointer->Sources())
            sources.push_back(AutomationJson{
                {"id", source->SourceId()}, {"name", source->SourceName()}, {"kind", PointerKindName(source->Kind())}});
        if (cerfcore::PointerSource* current = pointer->Active()) active = current->SourceId();
    } else {
        auto& keyboard = dynamic_cast<cerfcore::KeyboardRouter&>(object);
        for (cerfcore::KeyboardInput* source : keyboard.Sources())
            sources.push_back(AutomationJson{{"id", source->SourceId()}, {"name", source->SourceName()}});
        if (cerfcore::KeyboardInput* current = keyboard.Active()) active = current->SourceId();
    }
    return AutomationJson{{"active", std::move(active)}, {"sources", std::move(sources)}};
}

}
