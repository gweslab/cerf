#pragma once
#include "../../core/service.h"
#include "imx51_gpu3d_packet.h"
#include <array>
#include <unordered_map>

class StateWriter;
class StateReader;

class Imx51Gpu3dContext : public Service {
public:
    using Service::Service;
    bool ShouldRegister() override;
    void Load(const Imx51Gpu3dPacket& packet, std::unordered_map<uint32_t, uint32_t>& registers, uint32_t mmu_config);
    void ShadowWrite(uint32_t index, uint32_t value, uint32_t mmu_config);
    void SaveState(StateWriter& writer);
    void RestoreState(StateReader& reader);
private:
    struct Bank {
        uint32_t address = 0;
        bool     enabled = false;
        uint8_t  pad[3]  = {};

        template <typename F>
        static constexpr void Visit(Bank& b, F& field) {
            field("address", b.address);
            field("enabled", b.enabled);
            field.Skip(b.pad);
        }
    };
    std::array<Bank, 3> banks_{};
};
