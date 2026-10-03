#pragma once

#include "service.h"

#include <string>

class DeviceNotSelectedService : public Service {
public:
    using Service::Service;
    [[noreturn]] void Halt(const std::string& global_config_path);
};
