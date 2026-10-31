#pragma once

#include <cerfcore/core/service.h>

namespace cerffrontend {

class GuestCanvasTurn : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    int LogicalQuarter(int presentation_quarter) const;
};

}
