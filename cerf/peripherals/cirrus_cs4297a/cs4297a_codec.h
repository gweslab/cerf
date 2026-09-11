#pragma once

#include "../../core/service.h"
#include "../../state/state_stream.h"

#include <cstdint>

/* Cirrus CS4297A Datasheet DS318PP6. */
class Cs4297aCodec final : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    void Reset();
    void WarmReset();
    uint16_t ReadRegister(uint32_t reg, bool link_ready) const;
    void WriteRegister(uint32_t reg, uint16_t value);
    bool DacReady(bool link_ready) const;
    bool AdcReady(bool link_ready) const;
    bool LinkPowered() const;

    void SaveState(StateWriter& writer) const;
    void RestoreState(StateReader& reader);

private:
    uint16_t PowerStatusValue(bool link_ready) const;

    uint16_t registers_[128]{};
};
