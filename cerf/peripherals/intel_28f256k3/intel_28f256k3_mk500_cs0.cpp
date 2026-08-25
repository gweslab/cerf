#include "intel_28f256k3.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"

namespace {

/* symbol_mk500 dump.bin OEMAddressTable 0x00001E80: pa=0x00000000 size 64 MB.
   symbol_mk500 MK500c50XenMO0152XX.bin 0x027847: mfr 0x0089 device 0x8803 array
   0x04000000 erase 0x00040000 = 2x the 32 MB array and 0x20000 block of the x16
   28F256K3 in Intel StrataFlash K3/K18 order 290737 section 2.6 => 2 in parallel. */
class Intel28F256K3Mk500Cs0 : public Intel28F256K3 {
public:
    using Intel28F256K3::Intel28F256K3;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::SymbolMk500;
    }

    uint32_t MmioBase() const override { return 0x00000000u; }
    uint32_t MmioSize() const override { return 0x04000000u; }

    void WriteByte(uint32_t addr, uint8_t v) override {
        Trace("w8", addr, v);
        Intel28F256K3::WriteByte(addr, v);
    }
    void WriteHalf(uint32_t addr, uint16_t v) override {
        Trace("w16", addr, v);
        Intel28F256K3::WriteHalf(addr, v);
    }
    void WriteWord(uint32_t addr, uint32_t v) override {
        Trace("w32", addr, v);
        Intel28F256K3::WriteWord(addr, v);
    }

protected:
    uint32_t Parallel() const override { return 2u; }

private:
    void Trace(const char* op, uint32_t addr, uint32_t v) {
        if (++writes_ <= 64u)
            LOG(Periph, "[MK500 NOR] %s 0x%08X = 0x%08X\n", op, addr, v);
    }

    uint32_t writes_ = 0;
};

}  /* namespace */

REGISTER_SERVICE(Intel28F256K3Mk500Cs0);
