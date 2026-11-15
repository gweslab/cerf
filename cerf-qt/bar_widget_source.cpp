#include "bar_widget_source.h"

#include "bar_widgets.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/machine_object_tree.h>

#include <algorithm>

namespace cerffrontend {

void BarWidgetSource::OnReady() {
    auto& tree = emu_.Get<cerfcore::MachineObjectTree>();
    tree.Subscribe([this](const cerfcore::MachineEvent& event) {
        if (event.kind == cerfcore::MachineEventKind::kAdded && event.parent == nullptr) Offer(event.object);
    });
    for (cerfcore::MachineObject* object : tree.Roots()) Offer(object);
}

void BarWidgetSource::Offer(cerfcore::MachineObject* object) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (std::find(offered_.begin(), offered_.end(), object) != offered_.end()) return;
        offered_.push_back(object);
    }
    std::unique_ptr<BarWidget> widget = Create(*object);
    if (widget) emu_.Get<BarWidgets>().Add(std::move(widget), object);
}

}
