#pragma once

#include "../core/service.h"

#define NOMINMAX
#include <windows.h>

#include <cstdint>
#include <string>

class LiveCustomizationsTransaction : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;

    bool Open(HWND owner, bool force_reboot);

private:
    void Apply(std::string reboot, uint32_t prev_w, uint32_t prev_h);
};
