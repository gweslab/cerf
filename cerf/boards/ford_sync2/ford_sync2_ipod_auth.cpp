#include "../../socs/spi_slave.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "ford_sync_2_id.h"
#include "../../socs/imx51/imx51_ecspi1.h"
#include "../../socs/imx51/imx51_gpio4.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

/* Ford SYNC2 iPod Authentication Coprocessor (ipdacp.dll) on eCSPI1: the verify
   sub_C0D82F20 reboots unless the eCSPI transfer completes and >=1 of identity
   regs 0..3 reads non-0xFF. Wire protocol (sub_C0D83AC0): clock [reg][len] then
   len zero bytes; the chip returns the register's bytes during the zero phase. */
class FordSync2IpodAuth : public SpiSlave {
public:
    using SpiSlave::SpiSlave;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::FordSync2;
    }

    void OnReady() override {
        emu_.Get<Imx51Ecspi1>().AttachSlave(this);
        /* SOMI ready = GPIO4.23 (ipdacp DDKGpioReadDataPin(port 3, pin 23) reads
           GPIO4 PSR - cspddk's port table is 0-based). Must read high or the
           ready-wait sub_C0D8383C times out and IPDMonitorThread reboots; the chip
           has no processing delay in CERF, so hold it high. */
        emu_.Get<Imx51Gpio4>().SetInputPin(23, true);
    }

    uint8_t Exchange(uint8_t mosi) override {
        uint8_t miso = 0;
        switch (phase_) {
            case 0: reg_ = mosi; phase_ = 1; break;             /* command: register */
            case 1: len_ = mosi; data_idx_ = 0;                 /* command: byte count */
                    phase_ = (len_ == 0) ? 0u : 2u; break;
            case 2: miso = RegisterByte(reg_, data_idx_);       /* response data phase */
                    if (++data_idx_ >= len_) phase_ = 0; break;
        }
        return miso;
    }

    void SaveState(StateWriter& w) override {
        w.Write("reg", reg_); w.Write("len", len_); w.Write("data_idx", data_idx_); w.Write("phase", phase_);
    }
    void RestoreState(StateReader& r) override {
        r.Read("reg", reg_); r.Read("len", len_); r.Read("data_idx", data_idx_); r.Read("phase", phase_);
    }

private:
    /* The verify (sub_C0D82F20) requires identity regs 0..3 != 0xFF; the real
       Apple ACP values live in external hardware absent from every binary and
       can't be sourced, so every byte returns one non-0xFF present marker (regs
       4/5/0x11/0x20 are read for the info log, not checked). */
    static constexpr uint8_t kPresentMarker = 0x01;  /* any non-0xFF: chip present */
    static uint8_t RegisterByte(uint32_t /*reg*/, uint32_t /*idx*/) {
        return kPresentMarker;
    }

    uint32_t reg_ = 0, len_ = 0, data_idx_ = 0, phase_ = 0;
};

}  /* namespace */

REGISTER_SERVICE(FordSync2IpodAuth);
