#include "widget_menu_builder.h"

#include "link_opener.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/host_widget.h>
#include <cerfcore/host/host_widget_registry.h>

#include <type_traits>
#include <utility>

namespace cerffrontend {

REGISTER_SERVICE(WidgetMenuBuilder);

namespace {

void Separate(std::vector<MenuItem>& out) {
    if (!out.empty() && !out.back().label.empty()) out.push_back(MenuItem{});
}

void Trim(std::vector<MenuItem>& out) {
    while (!out.empty() && out.back().label.empty()) out.pop_back();
}

const char* InsertLabel(cerfcore::SlotKind kind) {
    switch (kind) {
        case cerfcore::SlotKind::kPcCard:
        case cerfcore::SlotKind::kSerialPort: return "Insert card";
        case cerfcore::SlotKind::kUsbDisk:
        case cerfcore::SlotKind::kSdCard:     return "Insert media";
    }
    return "Insert";
}

}

std::vector<MenuItem> WidgetMenuBuilder::Build(
    const std::vector<cerfcore::WidgetControl>& controls) {
    std::vector<MenuItem> out;
    Append(out, controls);
    Trim(out);
    return out;
}

std::vector<MenuItem> WidgetMenuBuilder::BuildAllWidgets() {
    std::vector<MenuItem> out;
    const auto            ordered = emu_.Get<cerfcore::HostWidgetRegistry>().Ordered();
    for (auto it = ordered.rbegin(); it != ordered.rend(); ++it) {
        cerfcore::HostWidget* w     = *it;
        std::vector<MenuItem> items = Build(w->Controls());
        if (items.empty())
            out.push_back(MenuItem::Info(w->WidgetName()));
        else if (items.size() == 1 && items[0].submenu.empty())
            out.push_back(std::move(items[0]));
        else
            out.push_back(MenuItem::Submenu(w->WidgetName(), std::move(items)));
    }
    return out;
}

void WidgetMenuBuilder::Append(std::vector<MenuItem>& out,
                               const std::vector<cerfcore::WidgetControl>& controls) {
    bool after_section = false;
    for (const cerfcore::WidgetControl& c : controls) {
        if (after_section) {
            Separate(out);
            after_section = false;
        }
        std::visit([&](const auto& v) {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, cerfcore::InfoControl>) {
                out.push_back(MenuItem::Info(v.text));
            } else if constexpr (std::is_same_v<T, cerfcore::LinkControl>) {
                out.push_back(MenuItem::Action(v.label, [this, url = v.url] { emu_.Get<LinkOpener>().Open(url); }));
            } else if constexpr (std::is_same_v<T, cerfcore::ActionControl>) {
                MenuItem item = MenuItem::Action(v.label, v.press);
                item.enabled  = v.enabled;
                out.push_back(std::move(item));
            } else if constexpr (std::is_same_v<T, cerfcore::ToggleControl>) {
                MenuItem item = MenuItem::Check(v.label, v.value, {});
                item.enabled  = v.enabled;
                if (v.set) item.on_click = [set = v.set, next = !v.value] { set(next); };
                out.push_back(std::move(item));
            } else if constexpr (std::is_same_v<T, cerfcore::ChoiceControl>) {
                for (const cerfcore::ChoiceOption& o : v.options) {
                    MenuItem item = MenuItem::Radio(o.label, o.id == v.selected, {});
                    if (v.select) item.on_click = [select = v.select, id = o.id] { select(id); };
                    out.push_back(std::move(item));
                }
            } else if constexpr (std::is_same_v<T, cerfcore::SlotControl>) {
                AppendSlot(out, v);
            } else if constexpr (std::is_same_v<T, cerfcore::GroupControl>) {
                if (v.label.empty()) {
                    Separate(out);
                    Append(out, v.children);
                    after_section = true;
                } else {
                    MenuItem item = MenuItem::Submenu(v.label, {});
                    Append(item.submenu, v.children);
                    Trim(item.submenu);
                    out.push_back(std::move(item));
                }
            }
        }, c.control);
    }
}

void WidgetMenuBuilder::AppendSlot(std::vector<MenuItem>& out, const cerfcore::SlotControl& slot) {
    if (!slot.inserted) {
        out.push_back(MenuItem::Submenu(InsertLabel(slot.kind), Entries(slot.available)));
        return;
    }

    out.push_back(MenuItem::Info(slot.inserted->label));
    out.push_back(MenuItem::Action("Eject", slot.eject));
    out.push_back(MenuItem::Submenu("Eject and insert", Entries(slot.available)));

    if (!slot.inserted_controls.empty()) {
        Separate(out);
        Append(out, slot.inserted_controls);
    }
}

std::vector<MenuItem> WidgetMenuBuilder::Entries(const std::vector<cerfcore::SlotEntry>& entries) {
    std::vector<MenuItem> out;
    for (const cerfcore::SlotEntry& e : entries) {
        MenuItem item;
        item.label   = e.label;
        item.enabled = e.enabled;
        if (e.variants.empty() && e.details.empty()) {
            item.on_click = e.insert;
            out.push_back(std::move(item));
            continue;
        }
        if (!e.variants.empty()) {
            item.submenu = Entries(e.variants);
        } else if (e.insert) {
            item.submenu.push_back(MenuItem::Action("Insert", e.insert));
        }
        if (!e.details.empty()) {
            Separate(item.submenu);
            Append(item.submenu, e.details);
            Trim(item.submenu);
        }
        out.push_back(std::move(item));
    }
    return out;
}

}
