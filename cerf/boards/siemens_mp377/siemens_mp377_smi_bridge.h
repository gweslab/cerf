#pragma once

#include "../../core/service.h"

#include <atomic>
#include <cstdint>

class StateReader;
class StateWriter;

namespace siemens_mp377 {

class SiemensMp377SmiBridge : public Service {
public:
    using Service::Service;

    static constexpr int kCascadeSource = 24;
    static constexpr uint32_t kSm501MasterBit = 0x00000100u;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t Sm501MasterStatus() const;
    void AssertPending();
    void ClearPending();

    uint32_t Read(uint32_t address) const;
    void Write(uint32_t address, uint32_t value);

    void SaveState(StateWriter& writer) const;
    void RestoreState(StateReader& reader);
    void PostRestoreState();

private:
    void Reset();
    static constexpr uint32_t kBridgeStatusBit = 0x00000001u;
    static constexpr uint32_t kBridgeValidStatusBits = kBridgeStatusBit;

    void AssertCascade();
    void DeassertCascade();

    std::atomic<uint32_t> master_pending_{0u};
    std::atomic<uint32_t> bridge_status_{0u};
    std::atomic<uint32_t> bridge_enable_{0xFFFFFFFFu};
};

} // namespace siemens_mp377
