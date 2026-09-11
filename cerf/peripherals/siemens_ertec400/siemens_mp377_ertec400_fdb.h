#pragma once

#include "../../core/service.h"

#include <cstdint>

class SiemensMp377Ertec400Fdb final : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    uint32_t ExecutePrimary(uint32_t value);

private:
    void Clear();
    uint32_t Reserve(uint32_t parameter);
    void Publish(uint32_t parameter);
};
