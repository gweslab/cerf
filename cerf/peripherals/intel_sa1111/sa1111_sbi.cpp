#include "../peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "../peripheral_dispatcher.h"
#include "../../state/state_stream.h"

namespace {

/* SA-1111 System Bus Interface (Developer's Manual Table 3-12, base
   0x40000000): SKCR +0x00 R/W, SMCR +0x04 R/W, SKID +0x08 read-only.
   Reset SKCR=0x80 (RdyEn, Table 3-9), SMCR=0x35 (GTIM|DRAC=5|CLAT,
   Table 3-10); SKID identifies the part as 690CC2 (Table 3-11). CERF has
   no PLL/sleep machinery, so SKCR's clock/PLL/sleep/test bits store with
   no side effect. */
class Sa1111Sbi : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Jornada720;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x40000000u; }
    uint32_t MmioSize() const override { return 0x00000200u; }

    uint32_t ReadWord(uint32_t addr) override {
        switch (addr - MmioBase()) {
            case 0x00: return skcr_;
            case 0x04: return smcr_;
            case 0x08: return 0x690CC200u;   /* SKID - SA-1111 identity, rev 0. */
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        switch (addr - MmioBase()) {
            case 0x00: skcr_ = value; return;
            case 0x04: smcr_ = value; return;
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

    void SaveState(StateWriter& w) override {
        w.Write("skcr", skcr_);
        w.Write("smcr", smcr_);
    }
    void RestoreState(StateReader& r) override {
        r.Read("skcr", skcr_);
        r.Read("smcr", smcr_);
    }

private:
    uint32_t skcr_ = 0x80u;   /* RdyEn reset (Table 3-9). */
    uint32_t smcr_ = 0x35u;   /* GTIM|DRAC=5|CLAT reset (Table 3-10). */
};

}  /* namespace */

REGISTER_SERVICE(Sa1111Sbi);
