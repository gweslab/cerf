#pragma once

#include "widget_menu_model.h"

#include <cerfcore/core/service.h>
#include <cerfcore/host/machine_socket.h>

#include <string>
#include <vector>

namespace cerffrontend {

class SocketMenu : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    std::vector<MenuItem> Build(cerfcore::MachineSocket& socket, const char* insert_label);
    std::string           Detail(const cerfcore::InsertedItem& item) const;

private:
    std::vector<MenuItem> Entries(cerfcore::MachineSocket& socket);
    std::vector<MenuItem> Commands(cerfcore::MachineSocket& socket, const cerfcore::InsertableType& type);
    void                  Insert(cerfcore::MachineSocket& socket, const std::string& type_id,
                                 const std::string& command_id, const std::string& argument,
                                 const std::string& item_name);
    void                  AppendHints(const cerfcore::InsertableType& type, std::vector<MenuItem>& items);
    std::string           CommandLabel(const cerfcore::MachineSocket& socket, const cerfcore::InsertCommand& command,
                                       const cerfcore::InsertArgument* argument) const;
};

}
