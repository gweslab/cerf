#pragma once
#include "../../core/service.h"
#include <array>
#include <cstdint>
#include <span>
#include <unordered_map>
#include <vector>

using Imx51Gpu3dVec4 = std::array<float, 4>;
struct Imx51Gpu3dMemoryExport { Imx51Gpu3dVec4 address, data; };
struct Imx51Gpu3dShaderState {
    std::array<Imx51Gpu3dVec4, 64> registers{}, exports{};
    std::vector<Imx51Gpu3dMemoryExport> memory_exports;
    std::array<Imx51Gpu3dVec4, 64> gradients_x{}, gradients_y{};
    uint64_t gradient_mask = 0;
    uint64_t export_mask = 0;
    float texture_lod = 0;
    int32_t loop_address = 0;
    Imx51Gpu3dVec4 texture_gradients_x{}, texture_gradients_y{};
    bool killed = false;
};
class Imx51Gpu3dShader : public Service {
public:
    using Service::Service;
    bool ShouldRegister() override;
    void Run(std::span<const uint32_t> program, bool pixel,
             const std::unordered_map<uint32_t, uint32_t>& registers,
             uint32_t mmu_config, Imx51Gpu3dShaderState& state);
    void RunQuad(std::span<const uint32_t> program,
                 const std::unordered_map<uint32_t, uint32_t>& registers,
                 uint32_t mmu_config, std::array<Imx51Gpu3dShaderState, 4>& states);
private:
    void RunInvocations(std::span<const uint32_t> program, bool pixel,
                        const std::unordered_map<uint32_t, uint32_t>& registers,
                        uint32_t mmu_config, std::span<Imx51Gpu3dShaderState> states);
    void Alu(std::array<uint32_t, 3> words, bool pixel,
             const std::unordered_map<uint32_t, uint32_t>& registers,
             Imx51Gpu3dShaderState& state, bool& predicate, float& previous);
    void Fetch(std::array<uint32_t, 3> words,
               const std::unordered_map<uint32_t, uint32_t>& registers,
               uint32_t mmu_config, Imx51Gpu3dShaderState& state, bool predicate);
    uint32_t Register(const std::unordered_map<uint32_t, uint32_t>& registers, uint32_t index);
    [[noreturn]] void Reject(const char* reason, uint32_t value);
};
