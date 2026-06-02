#include "omap3530_prcm_stub_block.h"

namespace {

class Omap3530Lan9115 : public Omap3530PrcmStubBlock {
public:
    using Omap3530PrcmStubBlock::Omap3530PrcmStubBlock;
    uint32_t MmioBase() const override { return 0x15000000u; }
    uint32_t MmioSize() const override { return 0x00000100u; }

protected:
    const char* Label() const override { return "LAN9115"; }
    const char* RegisterName(uint32_t) const override { return nullptr; }
};

}  /* namespace */

REGISTER_SERVICE(Omap3530Lan9115);
