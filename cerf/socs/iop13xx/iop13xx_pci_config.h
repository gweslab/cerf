#pragma once

#include "../../core/service.h"

#include <cstdint>

class StateReader;
class StateWriter;

enum class Iop13xxPciMemoryMapResult {
    kNotBar,
    kMapped,
    kUnmapped,
};

class Iop13xxPciConfig : public Service {
public:
    using Service::Service;

    virtual uint32_t ReadPrimary(uint32_t occar) = 0;
    virtual bool WritePrimary(uint32_t occar, uint32_t value) = 0;
    virtual uint32_t ReadSecondary(uint32_t occar) = 0;
    virtual bool WriteSecondary(uint32_t occar, uint32_t value) = 0;
    virtual Iop13xxPciMemoryMapResult MapMemoryBar(uint32_t pci_address, uint32_t size,
                                                   uint32_t& model_address) const = 0;

    virtual void SaveState(StateWriter& writer) = 0;
    virtual void RestoreState(StateReader& reader) = 0;
};
