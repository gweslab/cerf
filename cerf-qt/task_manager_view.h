#pragma once

#include <cerfcore/core/service.h>

namespace cerffrontend {

class TaskManagerView : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    virtual void Show() = 0;
};

}
