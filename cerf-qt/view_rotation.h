#pragma once

#include "widget_menu_model.h"

#include <cerfcore/core/service.h>

namespace cerffrontend {

class ViewRotation : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    int  Quarter() const { return quarter_; }
    void     Rotate(int quarters);
    MenuItem MenuRow();

private:
    int quarter_ = 0;
};

}
