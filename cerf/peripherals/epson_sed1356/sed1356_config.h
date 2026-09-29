#pragma once

#include "../../core/service.h"

#include <cstdint>
#include <functional>

class Sed1356Config : public Service {
public:
    using Service::Service;

    /* PA of the controller register window (host-bus base): REG[000h] sits
       here, the BitBLT aperture at +0x100000, the display buffer at
       +0x200000. */
    virtual uint32_t HostWindowBase() const = 0;

    /* Populated display-buffer bytes (S1D13806 embedded SDRAM = 0x140000;
       Jornada SED1356 external buffer = 0x80000). Accesses across the 2 MB
       display-buffer aperture alias within this size. */
    virtual uint32_t DisplayBufferBytes() const = 0;

    /* REG[000h] product/revision code readback (product in bits 7:2, revision
       in 1:0). S1D13806 = product 0x7 (Linux s1d13xxxfb.h S1D13806_PROD_ID);
       S1D13506 = product 0x4. */
    virtual uint8_t ProductRevCode() const = 0;

    /* SED1356 §8.1 reset-lock (REG[001h].7): only REG[000h]/[001h] decode until
       software clears it. The S1D13806 has no such gate - its driver reads
       REG[004h] before clearing REG[001h]. */
    virtual bool RegMemSelectLockedAtReset() const = 0;

    virtual uint64_t BusClockHz() const = 0;
    virtual void     RegisterBusClockListener(std::function<void()> fn) = 0;
};
