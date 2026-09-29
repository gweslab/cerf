#pragma once

#include <cstdint>
#include <functional>
#include <vector>

#include "../../core/service.h"

struct MipsCpuState;

class Tx39ConfigRegister : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t ReducedFrequency() const;
    void     RegisterReducedFrequencyListener(std::function<void()> fn);

    static void __fastcall Mtc0Helper(uint32_t value, Tx39ConfigRegister* reg);

private:
    void ApplyReset();

    MipsCpuState*                      cpu_state_ = nullptr;
    std::vector<std::function<void()>> rf_listeners_;
};
