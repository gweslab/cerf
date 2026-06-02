#pragma once
#include "service.h"
#include "device_config.h"
#include <string>

struct CerfConfig;

class ConfigLoader : public Service {
public:
    explicit ConfigLoader(CerfEmulator& emu) : Service(emu) {}

    void Load(const CerfConfig& cli, int argc, char** argv);

private:
    void ApplyAdoptedGuestAdditionsResolution(DeviceConfig& config);

    std::string cerf_dir_;
};
