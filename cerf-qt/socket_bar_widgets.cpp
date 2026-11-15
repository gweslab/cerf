#include "bar_widget_source.h"
#include "socket_menu.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/machine_socket.h>

#include <memory>
#include <string>

namespace cerffrontend {

namespace {

const char* PcCardIcon(const std::string& type_id) {
    if (type_id == "cf") return "pcmcia_enabled_cf";
    if (type_id == "hpvga") return "pcmcia_enabled_vga";
    if (type_id == "ne2000" || type_id == "ne2000_3v3") return "pcmcia_enabled_ethernet";
    if (type_id == "serial_fwd") return "pcmcia_enabled_serial_com";
    if (type_id == "serial") return "pcmcia_enabled_serial_modem";
    return "pcmcia_enabled";
}

class SocketBarWidget final : public BarWidget {
public:
    SocketBarWidget(cerfcore::CerfEmulator& emu, cerfcore::MachineSocket& socket) : emu_(emu), socket_(socket) {}

    std::string Name() const override { return socket_.ObjectName(); }

    BarGroup Group() const override {
        switch (socket_.ObjectKind()) {
            case cerfcore::MachineObjectKind::kSerialPort:  return BarGroup::Network;
            case cerfcore::MachineObjectKind::kMediaSocket: return BarGroup::Usb;
            default:                                        return BarGroup::Pcmcia;
        }
    }

    BarIcon Icon() const override { return ResourceIcon{IconName()}; }

    std::string Tooltip() const override {
        const auto inserted = socket_.Inserted();
        if (socket_.ObjectKind() == cerfcore::MachineObjectKind::kMediaSocket)
            return Name() + ": " + (inserted ? inserted->name : std::string("Empty"));
        if (!inserted) return Name() + " - empty";
        return Name() + " - " + emu_.Get<SocketMenu>().Detail(*inserted);
    }

    std::vector<MenuItem> Menu() override {
        const char* insert = "Insert card";
        if (socket_.ObjectKind() == cerfcore::MachineObjectKind::kSerialPort) insert = "Insert cable";
        if (socket_.ObjectKind() == cerfcore::MachineObjectKind::kMediaSocket) insert = "Insert media";
        return emu_.Get<SocketMenu>().Build(socket_, insert);
    }

    uint64_t RxCount() const override { return socket_.RxCount(); }
    uint64_t TxCount() const override { return socket_.TxCount(); }

private:
    std::string IconName() const {
        const auto inserted = socket_.Inserted();
        switch (socket_.ObjectKind()) {
            case cerfcore::MachineObjectKind::kSerialPort:
                if (!inserted) return "serial";
                return inserted->type_id == "modem" ? "serial_modem" : "serial_com";
            case cerfcore::MachineObjectKind::kMediaSocket:
                return socket_.Accepted().front().id == "sd_card" ? "sd_map" : "usb";
            default:
                return inserted ? PcCardIcon(inserted->type_id) : "pcmcia";
        }
    }

    cerfcore::CerfEmulator&  emu_;
    cerfcore::MachineSocket& socket_;
};

class SocketBarWidgetSource final : public BarWidgetSource {
public:
    using BarWidgetSource::BarWidgetSource;

protected:
    std::unique_ptr<BarWidget> Create(cerfcore::MachineObject& object) override {
        auto* socket = dynamic_cast<cerfcore::MachineSocket*>(&object);
        if (!socket) return nullptr;
        return std::make_unique<SocketBarWidget>(emu_, *socket);
    }
};

}

REGISTER_SERVICE(SocketBarWidgetSource);

}
