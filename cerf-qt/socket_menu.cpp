#include "socket_menu.h"

#include "link_opener.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/user_alert.h>

#include <cstdio>
#include <utility>
#include <variant>

namespace cerffrontend {

REGISTER_SERVICE(SocketMenu);

namespace {

constexpr char kActiveSyncUrl[]    = "https://cerf.cx/activesync";
constexpr char kGettingOnlineUrl[] = "https://cerf.cx/getting-online";

bool IsForward(const std::string& type_id) { return type_id == "serial_fwd" || type_id == "forward"; }
bool IsModem(const std::string& type_id) { return type_id == "serial" || type_id == "modem"; }

}

std::string SocketMenu::CommandLabel(const cerfcore::MachineSocket& socket, const cerfcore::InsertCommand& command,
                                     const cerfcore::InsertArgument* argument) const {
    if (command.id == "insert") return argument ? argument->name : "Insert";
    if (command.id == "insert_bundled") {
        if (socket.ObjectKind() == cerfcore::MachineObjectKind::kMediaSocket) return argument->name;
        return "Insert - " + argument->name;
    }
    if (command.id == "choose_image") return "Choose image...";
    if (command.id == "choose_default_image") return "Choose default image (CF.IMG)";
    if (command.id == "generate_fat16") return "Generate FAT16 into CF.IMG and choose it...";
    if (command.id == "generate_fat32") return "Generate FAT32 into CF.IMG and choose it...";
    return command.id;
}

void SocketMenu::Insert(cerfcore::MachineSocket& socket, const std::string& type_id, const std::string& command_id,
                        const std::string& argument, const std::string& item_name) {
    if (socket.Insert(type_id, command_id, argument) == cerfcore::InsertStatus::kAccepted) return;
    emu_.Get<cerfcore::UserAlert>().Post(cerfcore::AlertLevel::kWarning, socket.ObjectName(),
                                         item_name + " is no longer available.", [] {});
}

std::vector<MenuItem> SocketMenu::Commands(cerfcore::MachineSocket& socket, const cerfcore::InsertableType& type) {
    std::vector<MenuItem> items;
    for (const cerfcore::InsertCommand& command : type.commands) {
        if (command.arguments.empty()) {
            items.push_back(MenuItem::Action(CommandLabel(socket, command, nullptr),
                                             [this, &socket, type_id = type.id, cmd = command.id, name = type.name] {
                                                 Insert(socket, type_id, cmd, {}, name);
                                             }));
            continue;
        }
        for (const cerfcore::InsertArgument& argument : command.arguments)
            items.push_back(MenuItem::Action(
                CommandLabel(socket, command, &argument),
                [this, &socket, type_id = type.id, cmd = command.id, arg = argument.id, name = argument.name] {
                    Insert(socket, type_id, cmd, arg, name);
                }));
    }
    return items;
}

void SocketMenu::AppendHints(const cerfcore::InsertableType& type, std::vector<MenuItem>& items) {
    std::vector<MenuItem> hints;
    if (type.id == "hpvga") hints.push_back(MenuItem::Info("Only HP devices include the driver"));
    if (IsForward(type.id)) {
        if (type.commands.empty()) hints.push_back(MenuItem::Info("   (no host serial ports found)"));
        hints.push_back(MenuItem::Action("Connecting to ActiveSync tutorial",
                                         [this] { emu_.Get<LinkOpener>().Open(kActiveSyncUrl); }));
    }
    if (IsModem(type.id))
        hints.push_back(MenuItem::Action("Getting online tutorial",
                                         [this] { emu_.Get<LinkOpener>().Open(kGettingOnlineUrl); }));
    if (hints.empty()) return;
    if (!items.empty()) items.push_back(MenuItem{});
    for (MenuItem& hint : hints) items.push_back(std::move(hint));
}

std::vector<MenuItem> SocketMenu::Entries(cerfcore::MachineSocket& socket) {
    const std::vector<cerfcore::InsertableType> types = socket.Accepted();
    std::vector<MenuItem>                       out;
    if (types.size() == 1) {
        out = Commands(socket, types.front());
        AppendHints(types.front(), out);
        return out;
    }
    for (const cerfcore::InsertableType& type : types) {
        std::vector<MenuItem> commands = Commands(socket, type);
        const bool            plain    = type.commands.size() == 1 && type.commands.front().id == "insert" &&
                                         type.commands.front().arguments.empty();
        std::vector<MenuItem> hinted;
        AppendHints(type, hinted);
        if (plain && hinted.empty()) {
            MenuItem item = std::move(commands.front());
            item.label    = type.name;
            out.push_back(std::move(item));
            continue;
        }
        AppendHints(type, commands);
        out.push_back(MenuItem::Submenu(type.name, std::move(commands)));
    }
    return out;
}

std::vector<MenuItem> SocketMenu::Build(cerfcore::MachineSocket& socket, const char* insert_label) {
    const std::optional<cerfcore::InsertedItem> inserted = socket.Inserted();
    std::vector<MenuItem>                       out;
    if (!inserted) {
        out.push_back(MenuItem::Submenu(insert_label, Entries(socket)));
        return out;
    }
    out.push_back(MenuItem::Info(inserted->name));
    out.push_back(MenuItem::Action("Eject", [&socket] { socket.Eject(); }));
    out.push_back(MenuItem::Submenu("Eject and insert", Entries(socket)));
    if (const auto* net = std::get_if<cerfcore::NetworkCardFacts>(&inserted->facts)) {
        char mac[32];
        std::snprintf(mac, sizeof(mac), "MAC  %02X:%02X:%02X:%02X:%02X:%02X", net->mac[0], net->mac[1], net->mac[2],
                      net->mac[3], net->mac[4], net->mac[5]);
        out.push_back(MenuItem{});
        out.push_back(MenuItem::Info(mac));
    }
    return out;
}

std::string SocketMenu::Detail(const cerfcore::InsertedItem& item) const {
    if (const auto* storage = std::get_if<cerfcore::StorageCardFacts>(&item.facts)) {
        if (storage->capacity_bytes == 0) return item.name + " - image not found";
        return item.name + " - " + std::to_string(storage->capacity_bytes >> 20) + " MB";
    }
    if (const auto* net = std::get_if<cerfcore::NetworkCardFacts>(&item.facts)) {
        char text[48];
        std::snprintf(text, sizeof(text), "Ethernet  %02X:%02X:%02X:%02X:%02X:%02X", net->mac[0], net->mac[1],
                      net->mac[2], net->mac[3], net->mac[4], net->mac[5]);
        return text;
    }
    if (const auto* serial = std::get_if<cerfcore::SerialLinkFacts>(&item.facts))
        return item.name + " -> host " + serial->host_port;
    return item.name;
}

}
