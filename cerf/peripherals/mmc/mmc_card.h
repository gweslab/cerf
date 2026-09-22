#pragma once

#include "../../core/service.h"

#include <cstdint>
#include <vector>

class StateWriter;
class StateReader;

enum class MmcCommandResult {
    NoResponse,
    Short,
    Long,
};

class MmcCard : public Service {
public:
    using Service::Service;

    virtual uint32_t SlotIndex() const = 0;

    virtual MmcCommandResult Command(uint8_t index, uint32_t argument,
                                     uint32_t response[4]) = 0;

    virtual const std::vector<uint8_t>& ReadData() const = 0;

    virtual void NextBlock() = 0;

    virtual void EndDataPhase() = 0;

    virtual void Reset() = 0;

    virtual void SaveState(StateWriter&) {}
    virtual void RestoreState(StateReader&) {}
    virtual void PostRestore() {}
};
