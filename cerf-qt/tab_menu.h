#pragma once

#include "frontend_window.h"
#include "widget_menu_model.h"

#include <cerfcore/core/service.h>

namespace cerffrontend {

class TabMenu : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    MenuItem Item(FrontendWindow::Tab tab);
};

}
