#pragma once

#include "../../core/service.h"
#include "sa1111_serial_transfer.h"

#include <cstdint>

class StateReader;
class StateWriter;

class Sa1111SacL3 : public Service {
public:
    explicit Sa1111SacL3(CerfEmulator& emu);

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t Address() const { return car_; }
    void     WriteAddress(uint64_t now, uint32_t value, uint32_t sacr1);
    void     WriteData(uint64_t now, uint32_t value, uint32_t sacr1);
    uint32_t StatusBits(uint64_t now);
    void     ClearStatus(uint64_t now, uint32_t sascr);
    bool     DataSent(uint64_t now) const;

    void OnSacr1Write(uint64_t now, uint32_t sacr1);
    void OnClockChange(uint64_t now);
    void Reset(uint64_t now, bool chip);

    void Save(StateWriter& w, uint64_t now);
    void Restore(StateReader& r, uint64_t now);

private:
    void Settle(uint64_t now);
    void RequireBusModelled(uint32_t sacr1) const;
    void RequireClocks() const;

    Sa1111SerialTransfer xfer_;
    uint32_t             car_       = 0;
    bool                 addressed_ = false;
    bool                 data_      = false;
    bool                 sent_      = false;
};
