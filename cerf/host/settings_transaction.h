#pragma once

#include "../core/service.h"

#define NOMINMAX
#include <windows.h>

class SettingsTransaction : public Service {
public:
    using Service::Service;

    bool Open(HWND owner);
};
