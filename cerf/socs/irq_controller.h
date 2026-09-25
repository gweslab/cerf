#pragma once

#include "../core/service.h"

#include <cstdint>

class IrqController : public Service {
public:
    using Service::Service;
    ~IrqController() override = default;

    virtual void AssertIrq   (int source_bit)                          = 0;
    virtual void AssertSubIrq(int main_source_bit, int sub_source_bit) = 0;
    virtual void DeAssertIrq (int /*source_bit*/) {}
    virtual void PulseIrq    (int source_bit);
    virtual void SetSharedIrqLevel(int source_bit, uint32_t /*contributor_bit*/, bool asserted) {
        if (asserted)
            AssertIrq(source_bit);
        else
            DeAssertIrq(source_bit);
    }

    virtual uint32_t ReadPendingVector();

    static uint32_t __fastcall ReadPendingVectorHelper(IrqController* intc);
};
