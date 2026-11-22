#pragma once

#include <cerfcore/core/callback_list.h>
#include <cerfcore/core/service.h>

#include <functional>
#include <mutex>

namespace cerffrontend {

class HostHoldsRelease : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override;
    void Add(std::function<void()> release);

private:
    void ReleaseAll();

    std::mutex               mtx_;
    cerfcore::CallbackList<> releases_;
};

}
