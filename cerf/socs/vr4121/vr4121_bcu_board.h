#pragma once

#include "../../core/service.h"

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

struct Vr4121DramWiring {
    bool                    dbus32 = false;
    std::array<uint32_t, 4> bank_chip_bytes{};
};

struct Vr4121BcuBootWrite {
    uint32_t offset = 0;
    uint16_t value  = 0;
};

class Vr4121BcuBoard : public Service {
public:
    using Service::Service;

    virtual bool Sdram() const = 0;

    virtual std::optional<Vr4121DramWiring> DramWiring() const = 0;

    virtual std::vector<Vr4121BcuBootWrite> KernelEntryWrites() const = 0;
};
