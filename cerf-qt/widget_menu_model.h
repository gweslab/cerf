#pragma once

#include <functional>
#include <string>
#include <vector>

namespace cerffrontend {

struct MenuItem {
    std::string           label;
    bool                  enabled   = true;
    bool                  checkable = false;
    bool                  checked   = false;
    bool                  radio     = false;
    std::function<void()> on_click;
    std::vector<MenuItem> submenu;

    static MenuItem Action(std::string label, std::function<void()> on_click);
    static MenuItem Check(std::string label, bool checked, std::function<void()> on_click);
    static MenuItem Radio(std::string label, bool checked, std::function<void()> on_click);
    static MenuItem Info(std::string label);
    static MenuItem Submenu(std::string label, std::vector<MenuItem> items);
};

}
