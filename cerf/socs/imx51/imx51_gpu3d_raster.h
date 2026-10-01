#pragma once
#include "../../core/service.h"
#include "imx51_gpu3d_shader.h"
class Imx51Gpu3dRaster : public Service {
public:
    using Service::Service;
    bool ShouldRegister() override;
    void SaveState(class StateWriter& writer);
    void RestoreState(class StateReader& reader);
    void PowerOnReset();
    void Triangle(const std::array<Imx51Gpu3dShaderState,3>& vertices,
        const std::unordered_map<uint32_t,uint32_t>& registers,
        std::span<const uint32_t> pixel_program, uint32_t mmu_config);
private:
    struct RasterWrites {
        struct Pixel { uint8_t* target; std::array<uint8_t,4> data; uint32_t bytes; };
        std::vector<Pixel> pixels;
        uint32_t binding, pitch;
    };
    void RasterizeTriangle(const std::array<Imx51Gpu3dShaderState,3>& vertices,
        const std::array<Imx51Gpu3dShaderState,3>& depth_vertices,
        const std::unordered_map<uint32_t,uint32_t>& registers,
        std::span<const uint32_t> pixel_program, uint32_t mmu_config, RasterWrites& writes);
    std::array<uint8_t,0x20000> gmem_{};
    uint32_t gmem_binding_ = 0xFFFFFFFFu;
    uint32_t gmem_pitch_ = 0;
};
