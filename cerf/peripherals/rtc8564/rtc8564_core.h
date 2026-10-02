#pragma once

#include "../../core/service.h"

#include <cstdint>

class StateReader;
class StateWriter;

class Rtc8564Core : public Service {
public:
    using Service::Service;

    virtual void    Update()                              = 0;
    virtual void    WriteAt(uint8_t index, uint8_t value) = 0;
    virtual uint8_t ReadAt(uint8_t index)                 = 0;
    virtual bool    StopSet()                             = 0;
    virtual void    SaveState(StateWriter& writer)        = 0;
    virtual void    RestoreState(StateReader& reader)     = 0;
    virtual void    PostRestore()                         = 0;
};
