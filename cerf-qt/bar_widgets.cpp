#include "bar_widgets.h"

#include <cerfcore/core/cerf_emulator.h>

#include <algorithm>
#include <utility>

namespace cerffrontend {

REGISTER_SERVICE(BarWidgets);

void BarWidgets::Add(std::unique_ptr<BarWidget> widget, const cerfcore::MachineObject* object) {
    std::lock_guard<std::mutex> lk(mtx_);
    entries_.push_back(Entry{std::move(widget), object, next_id_++});
}

std::vector<BarWidget*> BarWidgets::Ordered() {
    std::vector<BarWidget*> out;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        for (const Entry& e : entries_)
            if (e.widget->Shown()) out.push_back(e.widget.get());
    }
    std::stable_sort(out.begin(), out.end(), [](const BarWidget* a, const BarWidget* b) {
        const int ga = static_cast<int>(a->Group());
        const int gb = static_cast<int>(b->Group());
        if (ga != gb) return ga < gb;
        return a->Name() < b->Name();
    });
    return out;
}

BarWidget* BarWidgets::ForObject(const cerfcore::MachineObject* object) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (const Entry& e : entries_)
        if (e.object == object) return e.widget.get();
    return nullptr;
}

uint64_t BarWidgets::IdOf(const BarWidget* widget) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (const Entry& e : entries_)
        if (e.widget.get() == widget) return e.id;
    return 0;
}

BarWidget* BarWidgets::Find(uint64_t id) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (const Entry& e : entries_)
        if (e.id == id) return e.widget.get();
    return nullptr;
}

}
