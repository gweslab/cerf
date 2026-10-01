#pragma once

#include "../../core/service.h"

#include <array>
#include <cstdint>
#include <functional>

enum class Imx51PowerGatedBlock : uint8_t { kVpu, kGpu3d, kGpu2d };

class Imx51PowerGateLine : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;

    void RegisterBlock(Imx51PowerGatedBlock block, std::function<void()> power_down);
    void PowerDown(Imx51PowerGatedBlock block);

private:
    std::array<std::function<void()>, 3> blocks_{};
};
