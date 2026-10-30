#include "widget_menu_model.h"

#include <utility>

namespace cerffrontend {

MenuItem MenuItem::Action(std::string label, std::function<void()> on_click) {
    MenuItem item;
    item.label    = std::move(label);
    item.on_click = std::move(on_click);
    return item;
}

MenuItem MenuItem::IconAction(std::string label, std::string icon, std::function<void()> on_click) {
    MenuItem item = Action(std::move(label), std::move(on_click));
    item.icon     = std::move(icon);
    return item;
}

MenuItem MenuItem::Check(std::string label, bool checked, std::function<void()> on_click) {
    MenuItem item  = Action(std::move(label), std::move(on_click));
    item.checkable = true;
    item.checked   = checked;
    return item;
}

MenuItem MenuItem::Radio(std::string label, bool checked, std::function<void()> on_click) {
    MenuItem item = Check(std::move(label), checked, std::move(on_click));
    item.radio    = true;
    return item;
}

MenuItem MenuItem::Info(std::string label) {
    MenuItem item;
    item.label   = std::move(label);
    item.enabled = false;
    return item;
}

MenuItem MenuItem::Submenu(std::string label, std::vector<MenuItem> items) {
    MenuItem item;
    item.label   = std::move(label);
    item.submenu = std::move(items);
    return item;
}

MenuItem MenuItem::Row(std::string label, std::vector<MenuItem> buttons) {
    MenuItem item;
    item.label = std::move(label);
    item.row   = std::move(buttons);
    return item;
}

}
