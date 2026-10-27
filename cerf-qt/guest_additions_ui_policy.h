#pragma once

#include <cerfcore/core/service.h>

#include <cstdint>

namespace cerffrontend {

class GuestAdditionsUiPolicy : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    bool LiveResizeAvailable() const;
    bool CeVersion(uint16_t& major, uint16_t& minor) const;
};

}
