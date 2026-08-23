#pragma once

#include "../core/service.h"

#define NOMINMAX
#include <windows.h>

#include <cstdint>
#include <span>

class HostResource : public Service {
public:
    using Service::Service;

    std::span<const uint8_t> Bytes(const wchar_t* name) const;
};
