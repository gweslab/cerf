#pragma once

#include <cerfcore/core/service.h>

namespace cerfcore {
class MachineGuestCalibration;
class MachineObject;
}

namespace cerffrontend {

class GuestCalibrationFallback : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    bool ShouldRegister() override;

    void Show();
    void EndCycle(bool pointer_switched_back);

private:
    cerfcore::MachineGuestCalibration* FindIn(const cerfcore::MachineObject* parent);
};

}
