#pragma once

#include "../../core/service.h"
#include "../../host/battery_widget.h"

class NecMobilePro700Battery : public Service {
public:
    explicit NecMobilePro700Battery(CerfEmulator& e) : Service(e), battery_(e) {}

    bool ShouldRegister() override;
    void OnReady() override;

    int FillPercent() const { return battery_.FillPercent(); }

private:
    void DriveAcPin();

    BatteryWidget battery_;
};
