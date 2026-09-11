#pragma once

#include "../../core/service.h"

#include <cstdint>

namespace siemens_mp377 {

class SiemensMp377Sm501Regs;

// SM501 Databook ch. 6 and ch. 17: power-mode gate/clock selection and GPIO
// pin multiplexing, including the MP377 board's CS4297A reset wiring.
class SiemensMp377Sm501PowerGpio : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void Initialize(SiemensMp377Sm501Regs& registers);
    uint32_t CurrentGate() const;
    uint32_t CurrentClock() const;
    bool IsGateEnabled(uint32_t gate_bit) const;
    void WritePowerModeControl(uint32_t value);
    bool IsAc97LinkMuxed() const;
    bool IsCodecResetDeasserted() const;
    uint32_t ReadGpioDataLow() const;
    uint32_t ReadGpioDirectionLow() const;
    void UpdateAc97Link();

private:
    uint32_t CurrentGateMask() const;
    uint32_t ActiveAc97GpioMuxMask() const;
};

} // namespace siemens_mp377
