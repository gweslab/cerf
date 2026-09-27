#pragma once

#include "../core/service.h"

#define NOMINMAX
#include <windows.h>

class HostFocusPolicy : public Service {
public:
    using Service::Service;

    bool MayActivate() const;

    void Show(HWND hwnd) const;
    void Raise(HWND hwnd) const;
    void Focus(HWND hwnd) const;
};
