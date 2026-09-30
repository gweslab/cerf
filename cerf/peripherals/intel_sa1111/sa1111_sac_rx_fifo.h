#pragma once

#include "../../core/service.h"

#include <cstdint>

class StateReader;
class StateWriter;

class Sa1111SacRxFifo : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;

    void Start(uint64_t pos);
    void Stop(uint64_t pos);
    void Clear(uint64_t pos);
    void ClearOverrun(uint64_t pos);

    bool     Running() const { return running_; }
    uint32_t Level(uint64_t pos) const;
    bool     Overrun(uint64_t pos) const;
    bool     ServiceRequest(uint64_t pos, bool enabled, uint32_t threshold) const;
    uint32_t StatusBits(uint64_t pos, bool enabled, uint32_t threshold) const;

    void Save(StateWriter& w, uint64_t pos) const;
    void Restore(StateReader& r, uint64_t pos);

private:
    uint64_t Received(uint64_t pos) const;

    bool     running_ = false;
    uint64_t pos0_    = 0;
    uint32_t level0_  = 0;
    bool     overrun_ = false;
};
