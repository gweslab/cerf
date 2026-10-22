#pragma once

#include <cerfcore/core/service.h>

namespace cerffrontend {

class StartupScale : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static constexpr int kDynamicMaxFactor = 2;

    int Factor(int primary_display_dpi) const;
};

}
