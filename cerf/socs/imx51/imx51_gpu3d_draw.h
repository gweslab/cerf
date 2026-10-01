#pragma once
#include "../../core/service.h"
#include "imx51_gpu3d_packet.h"
#include <array>
#include <span>
#include <unordered_map>

class StateWriter;
class StateReader;
struct Imx51Gpu3dShaderState;

class Imx51Gpu3dDraw : public Service {
public:
    using Service::Service;
    bool ShouldRegister() override;
    void Packet(const Imx51Gpu3dPacket& packet,
                std::unordered_map<uint32_t, uint32_t>& registers, uint32_t mmu_config);
    void SaveState(StateWriter& writer);
    void RestoreState(StateReader& reader);
    void PowerOnReset();

private:
    uint32_t Operand(const Imx51Gpu3dPacket& packet, uint32_t index, uint32_t mmu);
    uint32_t InstructionOffset(uint32_t stage, uint32_t start, uint32_t count);
    std::span<const uint32_t> Program(uint32_t stage);
    void Load(const Imx51Gpu3dPacket& packet, uint32_t mmu);
    void Store(const Imx51Gpu3dPacket& packet, uint32_t mmu);
    void Export(const Imx51Gpu3dShaderState& state, uint32_t mmu);
    void Draw(const Imx51Gpu3dPacket& packet,
              const std::unordered_map<uint32_t, uint32_t>& registers, uint32_t mmu);
    [[noreturn]] void Reject(const char* reason, uint64_t value);
    std::array<std::array<uint32_t, 1536>, 2> instructions_{};
    std::array<std::array<uint8_t, 1536>, 2> valid_{};
    std::array<uint32_t, 3> start_size_{};
    uint32_t bases_ = 0;
    uint32_t bin_base_ = 0;
};
