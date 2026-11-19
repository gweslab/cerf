#pragma once

#include "automation_server.h"

#include <cerfcore/core/service.h>
#include <cerfcore/host/machine_object.h>

namespace cerffrontend {

class AutomationObjectState : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    bool ShouldRegister() override;

    AutomationJson Of(cerfcore::MachineObject& object);
    AutomationJson PathJson(cerfcore::MachineObject& object);

private:
    static const char* KindName(cerfcore::MachineObjectKind kind);
    AutomationJson     State(cerfcore::MachineObject& object);
    AutomationJson     SocketState(cerfcore::MachineObject& object);
    AutomationJson     IndicatorState(cerfcore::MachineObject& object);
    AutomationJson     InputSourceState(cerfcore::MachineObject& object);
};

}
