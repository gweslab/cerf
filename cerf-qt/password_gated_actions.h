#pragma once

#include <cerfcore/core/service.h>

#include <functional>

namespace cerffrontend {

class PasswordGatedActions : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OpenCerfman(const std::function<void()>& action, const std::function<void()>& refused = {});
    void RunSignedIn(const std::function<void()>& action, const std::function<void()>& refused = {});

private:
    bool asking_ = false;
};

}
