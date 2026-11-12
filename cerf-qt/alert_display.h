#pragma once

#include <cerfcore/core/service.h>
#include <cerfcore/host/user_alert.h>

#include <string>

class AlertDisplay : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    virtual void Show(cerfcore::AlertLevel level, cerfcore::AlertPlacement placement, const std::string& title,
                      const std::string& text) = 0;
};
