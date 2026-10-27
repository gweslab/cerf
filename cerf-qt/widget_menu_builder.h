#pragma once

#include <cerfcore/core/service.h>
#include <cerfcore/host/widget_control.h>
#include "widget_menu_model.h"

#include <vector>

namespace cerffrontend {

class WidgetMenuBuilder : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    std::vector<MenuItem> Build(const std::vector<cerfcore::WidgetControl>& controls);
    std::vector<MenuItem> BuildAllWidgets();

private:
    void Append(std::vector<MenuItem>& out, const std::vector<cerfcore::WidgetControl>& controls);
    void AppendSlot(std::vector<MenuItem>& out, const cerfcore::SlotControl& slot);
    std::vector<MenuItem> Entries(const std::vector<cerfcore::SlotEntry>& entries);
};

}
