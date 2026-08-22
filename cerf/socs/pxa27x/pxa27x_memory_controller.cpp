#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

/* Intel PXA27x Developer's Manual 280000-001 Table 6-44 (page 6-85) "Memory
   Controller Register Summary": 0x4800_0000..0x4800_0064, "0x4800_0068-
   0x4800_FFFC reserved", "must be accessed only with word accesses". */
class Pxa27xMemoryController : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA27x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x48000000u; }
    uint32_t MmioSize() const override { return 0x00010000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    /* Table 6-44 (page 6-85) offsets; 0x0018, 0x0020 and 0x0024 name no
       register. */
    enum : uint32_t {
        kMdcnfg  = 0x00, kMdrefr  = 0x04, kMsc0      = 0x08, kMsc1    = 0x0C,
        kMsc2    = 0x10, kMecr    = 0x14, kSxcnfg    = 0x1C, kMcmem0  = 0x28,
        kMcmem1  = 0x2C, kMcatt0  = 0x30, kMcatt1    = 0x34, kMcio0   = 0x38,
        kMcio1   = 0x3C, kMdmrs   = 0x40, kBootDef   = 0x44, kArbCntl = 0x48,
        kBscntr0 = 0x4C, kBscntr1 = 0x50, kLcdbscntr = 0x54, kMdmrslp = 0x58,
        kBscntr2 = 0x5C, kBscntr3 = 0x60, kSa1110    = 0x64,
    };

    static bool IsRegister(uint32_t off);

    /* Reset rows, '?' cells taken as 0: Table 6-23 (page 6-43) MDCNFG,
       Table 6-26 (page 6-53) MDREFR, Table 6-28 (page 6-70) MSC0/1/2. */
    uint32_t regs_[(kSa1110 / 4u) + 1u] = {
        0x0B000B00u, 0x23CA4FFFu, 0x7FF07FF0u, 0x7FF07FF0u, 0x7FF07FF0u,
    };
};

bool Pxa27xMemoryController::IsRegister(uint32_t off) {
    switch (off) {
    case kMdcnfg:  case kMdrefr:  case kMsc0:      case kMsc1:
    case kMsc2:    case kMecr:    case kSxcnfg:    case kMcmem0:
    case kMcmem1:  case kMcatt0:  case kMcatt1:    case kMcio0:
    case kMcio1:   case kMdmrs:   case kArbCntl:   case kBscntr0:
    case kBscntr1: case kLcdbscntr: case kMdmrslp: case kBscntr2:
    case kBscntr3: case kSa1110:
        return true;
    default:
        return false;
    }
}

uint32_t Pxa27xMemoryController::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    /* Table 6-33 (page 6-75): BOOT_DEF bit 3 PKG_TYPE and bit 0 BOOT_SEL are
       access "R" pin straps; its Reset row is "? ... ? 1 ? ? *". */
    if (off == kBootDef) HaltUnsupportedAccess("ReadWord(BOOT_DEF strap)", addr, 0);
    if (IsRegister(off)) return regs_[off / 4u];
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa27xMemoryController::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    /* Table 6-33 (page 6-75): both BOOT_DEF fields are access "R". */
    if (off == kBootDef) HaltUnsupportedAccess("WriteWord(BOOT_DEF read-only)", addr, value);
    if (IsRegister(off)) { regs_[off / 4u] = value; return; }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Pxa27xMemoryController::SaveState(StateWriter& w) {
    w.WriteBytes(regs_, sizeof(regs_));
}

void Pxa27xMemoryController::RestoreState(StateReader& r) {
    r.ReadBytes(regs_, sizeof(regs_));
}

}  /* namespace */

REGISTER_SERVICE(Pxa27xMemoryController);
