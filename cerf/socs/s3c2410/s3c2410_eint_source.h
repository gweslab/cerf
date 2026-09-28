#pragma once

#include "../../core/service.h"

#include <cstdint>
#include <functional>
#include <vector>

/* S3C2410A UM p. 14-7: SRCPND EINT0 [0], EINT1 [1], EINT2 [2], EINT3 [3],
   EINT4_7 [4], EINT8_23 [5]. UM pp. 9-26/9-27: EINTMASK and EINTPEND serve
   "20 external interrupts (EINT[23:4])". */
class S3C2410EintSink {
public:
    virtual ~S3C2410EintSink() = default;

    virtual void DriveEintPin(int eint, bool level) = 0;

    virtual void ReassertHeldLevelEints(uint32_t cleared_srcpnd) = 0;
};

class S3C2410EintSource : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;

    void SetSink(S3C2410EintSink* sink);

    void DriveEintPin(int eint, bool level);

    void ReassertHeldLevelEints(uint32_t cleared_srcpnd);

    void RegisterUnmaskListener(std::function<void(uint32_t unmasked_intmsk)> fn);
    void NotifyUnmasked(uint32_t unmasked_intmsk);

private:
    S3C2410EintSink* sink_ = nullptr;
    std::vector<std::function<void(uint32_t)>> unmask_listeners_;
};
