#pragma once

#include "../../core/service.h"

#include <cstdint>

class StateReader;
class StateWriter;

class Iop13xxI2cDevice : public Service {
public:
    using Service::Service;

    virtual bool Address(uint8_t address_byte) = 0;
    virtual bool WriteByte(uint8_t value) = 0;
    virtual bool ReadByte(uint8_t& value) = 0;
    virtual void Stop() = 0;
    virtual void SaveState(StateWriter& writer) = 0;
    virtual void RestoreState(StateReader& reader) = 0;
    virtual void PostRestore() = 0;
};
