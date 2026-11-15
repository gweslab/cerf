#pragma once

#include "bar_icon.h"
#include "widget_menu_model.h"

#include <string>
#include <vector>

namespace cerffrontend {

enum class BarGroup : int {
    Storage = 0,
    Network,
    Pcmcia,
    Usb,
    Indicator,
    Power,
    Debug,
    GuestAdditions = 900,
    InputControl   = 1000,
    InputCapture   = 1100,
};

class BarWidget {
public:
    virtual ~BarWidget() = default;

    virtual std::string Name() const  = 0;
    virtual BarGroup    Group() const = 0;
    virtual BarIcon     Icon() const  = 0;
    virtual std::string Tooltip() const { return Name(); }
    virtual bool        Shown() const { return true; }
    virtual bool        IsEnabled() const { return true; }

    virtual bool                  PrimaryClick() { return false; }
    virtual std::vector<MenuItem> Menu() { return {}; }
    virtual bool                  MenuIsOneAction() const { return false; }

    virtual uint64_t RxCount() const { return 0; }
    virtual uint64_t TxCount() const { return 0; }
};

}
