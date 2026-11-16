#pragma once

#include "widget_menu_model.h"

#include <cerfcore/core/service.h>

#include <vector>

namespace cerffrontend {

class EnterpriseMenu : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    std::vector<MenuItem> Items();
};

}
