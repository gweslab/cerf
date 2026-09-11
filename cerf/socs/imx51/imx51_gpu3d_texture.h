#pragma once
#include "../../core/service.h"
#include "imx51_gpu3d_shader.h"
class Imx51Gpu3dTexture : public Service {
public:
    using Service::Service;
    bool ShouldRegister() override;
    Imx51Gpu3dVec4 Sample(const std::unordered_map<uint32_t,uint32_t>& registers,
        uint32_t mmu_config, uint32_t slot, const Imx51Gpu3dVec4& coordinates,
        std::array<uint32_t,3> instruction, const Imx51Gpu3dVec4* dx = nullptr, const Imx51Gpu3dVec4* dy = nullptr,
        float register_lod = 0);
};
