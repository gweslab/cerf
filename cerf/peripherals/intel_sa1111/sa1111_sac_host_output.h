#pragma once

#include "../../core/service.h"
#include "../../host/paced_wave_out.h"

#include <cstdint>

class Sa1111SacHostOutput : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;
    void OnShutdown() override;

    void SetRate(uint64_t fs_num, uint64_t fs_den);
    void Begin();
    void End();
    void Queue(const uint8_t* data, uint32_t bytes);
    void Drop();

private:
    PacedWaveOut out_;
    uint32_t     rate_   = 0;
    bool         active_ = false;
};
