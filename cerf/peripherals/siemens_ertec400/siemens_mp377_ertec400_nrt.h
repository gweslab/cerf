#pragma once

#include "../../core/service.h"

#include <cstddef>
#include <cstdint>
#include <memory>

class StateReader;
class StateWriter;

class SiemensMp377Ertec400Nrt final : public Service {
public:
    explicit SiemensMp377Ertec400Nrt(CerfEmulator& emu);
    ~SiemensMp377Ertec400Nrt() override;

    bool ShouldRegister() override;
    void OnReady() override;
    void OnShutdown() override;

    void Reset();
    void ConfigureRingAddress(uint32_t channel, bool receive, uint32_t asic_address);
    void ExecuteCommand(uint32_t channel, uint32_t command);

    uint32_t InterruptStatusHigh() const;
    void AcknowledgeInterrupt();
    void SetInterruptMaskHigh(uint32_t mask);

    void SaveState(StateWriter& writer) const;
    void RestoreState(StateReader& reader);
    void PostRestore();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
