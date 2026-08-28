#pragma once

#include "../../core/service.h"

#include <cstdint>
#include <mutex>

class StateWriter;
class StateReader;

/* VR4111 UM 11.2.4 p269 BCUERRSTREG (0x0B00 000C) D0 BERRST R/W1C; 11.4.6 p284
   Table 11-7; 15.2.1 p329 SYSINT1REG (0x0B00 0080) D10 WRBERRINTR. */
class Vr4111BusError : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    void NotifyIllegalWrite();

    uint16_t ReadStatus();
    void     WriteStatus(uint16_t value);

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);
    void PostRestore();

private:
    void Publish(bool level);

    std::mutex mtx_;
    bool       berrst_ = false;
};
