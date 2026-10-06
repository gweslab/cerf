#pragma once

#include "../../core/service.h"

class Ds1386Wiring : public Service {
public:
    using Service::Service;

    virtual void SetIntA(bool active) = 0;
    virtual void SetIntB(bool active) = 0;
};
