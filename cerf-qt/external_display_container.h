#pragma once

#include <cstdint>

class ExternalDisplayContainer {
public:
    virtual ~ExternalDisplayContainer() = default;

    virtual void SetSurfaceSize(uint32_t w, uint32_t h) = 0;
};
