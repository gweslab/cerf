#pragma once

#include "bar_widget.h"

#include <cerfcore/core/service.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace cerfcore {
class MachineObject;
}

namespace cerffrontend {

class BarWidgets : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void Add(std::unique_ptr<BarWidget> widget, const cerfcore::MachineObject* object = nullptr);
    std::vector<BarWidget*> Ordered();
    BarWidget*              ForObject(const cerfcore::MachineObject* object);
    uint64_t                IdOf(const BarWidget* widget);
    BarWidget*              Find(uint64_t id);

private:
    struct Entry {
        std::unique_ptr<BarWidget>     widget;
        const cerfcore::MachineObject* object = nullptr;
        uint64_t                       id     = 0;
    };

    std::mutex         mtx_;
    std::vector<Entry> entries_;
    uint64_t           next_id_ = 1;
};

}
