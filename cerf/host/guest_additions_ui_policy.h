#pragma once

#include "../core/service.h"

#include <cstdint>

class GuestAdditionsUiPolicy : public Service {
public:
    using Service::Service;

    bool LiveResizeAvailable() const;
    bool CeVersion(uint16_t& major, uint16_t& minor) const;
};
