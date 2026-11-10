#pragma once

#include <cerfcore/core/service.h>

#include <cstdint>
#include <string>
#include <vector>

namespace cerffrontend {

class ScreenshotStore : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    virtual bool Store(const std::vector<uint8_t>& png, const std::string& file_name) = 0;
};

}
