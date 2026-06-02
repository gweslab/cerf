#include "omap3530_prcm_stub_block.h"

namespace {

class Omap3530Sgx : public Omap3530PrcmStubBlock {
public:
    using Omap3530PrcmStubBlock::Omap3530PrcmStubBlock;
    uint32_t MmioBase() const override { return 0x50000000u; }
    uint32_t MmioSize() const override { return 0x00010000u; }
protected:
    const char* Label() const override { return "SGX"; }
    const char* RegisterName(uint32_t) const override { return nullptr; }
};

}  /* namespace */

REGISTER_SERVICE(Omap3530Sgx);
