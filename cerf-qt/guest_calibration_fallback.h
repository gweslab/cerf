#pragma once

#include <cerfcore/core/service.h>

namespace cerffrontend {

class GuestCalibrationFallback : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    bool ShouldRegister() override;

    void Show();
    void EndCycle(bool pointer_switched_back);
};

}
