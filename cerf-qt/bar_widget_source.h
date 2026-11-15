#pragma once

#include "bar_widget.h"

#include <cerfcore/core/service.h>

#include <memory>
#include <mutex>
#include <vector>

namespace cerfcore {
class MachineObject;
}

namespace cerffrontend {

class BarWidgetSource : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override;

protected:
    virtual std::unique_ptr<BarWidget> Create(cerfcore::MachineObject& object) = 0;

private:
    void Offer(cerfcore::MachineObject* object);

    std::mutex                                  mtx_;
    std::vector<const cerfcore::MachineObject*> offered_;
};

}
