#pragma once

#include <cerfcore/core/service.h>

class QtTheme : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void ApplyStyle();
    bool IsDark() const { return dark_; }

private:
    bool dark_ = false;
};
