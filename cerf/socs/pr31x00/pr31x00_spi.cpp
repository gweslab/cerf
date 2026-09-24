#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "pr31500_id.h"
#include "pr31700_id.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "pr31x00_intc.h"
#include "pr31x00_spi_slave.h"

#include <cstdint>

namespace {

constexpr uint32_t kBase = 0x10C00160u;

constexpr uint32_t kOffCtl    = 0x00u;   /* $160 */
constexpr uint32_t kOffData   = 0x04u;   /* $164 TXDATA (W) / RXDATA (R) */

/* SPI Control (§14.3.1): SPION<17>(R) EMPTY<16>(R) DELAYVAL[3:0]<15:12>
   BAUDRATE[3:0]<11:8> PHAPOL<5> CLKPOL<4> WORD<2> LSB<1> ENSPI<0>; bits 31-18,
   7-6 and 3 reserved. */
constexpr uint32_t kCtlWritable = 0x0000FF37u;
constexpr uint32_t kCtlRsvdOrRo = 0xFFFF00C8u;
constexpr uint32_t kCtlSpion    = 0x00020000u;
constexpr uint32_t kCtlEmpty    = 0x00010000u;
constexpr uint32_t kCtlEnSpi    = 0x00000001u;

/* SPIBUFAVAILINT = Interrupt Status 5 bit 21 (R3912.H:424; Status 5 = INTC set 4):
   the transmit-buffer-available LEVEL the guest busy-polls before loading TXDATA
   (§14.3.2). Free-running while ENSPI, NOT a per-byte event - a per-byte SetPending
   leaves each later byte's poll (sub_1EBD700) unasserted and hangs. */
constexpr uint32_t kStatus5Set     = 4u;
constexpr uint32_t kSpiBufAvailInt = 1u << 21;

class Pr31x00Spi : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        if (!bd) return false;
        const std::string_view soc = bd->GetSocId();
        return soc == SocId::Pr31500 || soc == SocId::Pr31700;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return 0x8u; }

    uint32_t ReadWord(uint32_t addr) override {
        switch (addr - kBase) {
            case kOffCtl:
                /* SPION and EMPTY report the Transmitter Holding and Shift Registers,
                   which are empty while no transfer is staged (§14.3.1). */
                return ctl_ | kCtlEmpty | ((ctl_ & kCtlEnSpi) ? kCtlSpion : 0u);

            /* §14.3.3: RXDATA[15:0] read-only, RESET = X, valid only after
               SPIRCVINT; an unstaged read returns the undefined Receiver
               Holding Register. */
            case kOffData: {
                auto* slave = emu_.TryGet<Pr31x00SpiSlave>();
                if (slave && slave->SpiRxHasByte()) return slave->SpiRxReadByte();
                return 0;
            }

            default:
                HaltUnsupportedAccess("PR31x00 SPI ReadWord", addr, 0);
        }
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        switch (addr - kBase) {
            case kOffCtl:
                /* SPION and EMPTY are read-only status; serial.dll sub_1EBD514 clears
                   ENSPI with a read-modify-write of CTL that reads them back, and a
                   write to a read-only bit is ignored (§14.3.1). */
                value &= ~(kCtlSpion | kCtlEmpty);
                if (value & kCtlRsvdOrRo) {
                    HaltUnsupportedAccess("PR31x00 SPI CTL reserved bit", addr, value);
                }
                ctl_ = value & kCtlWritable;
                emu_.Get<Pr31x00Intc>().SetSourceFreeRunning(
                    kStatus5Set, kSpiBufAvailInt, (ctl_ & kCtlEnSpi) != 0u);
                return;

            /* A TXDATA write loads the Transmitter Holding Register and clocks the
               character out to the slave (§14.3.2); WORD is clear on this bus, so
               only TXDATA[7:0] is valid. */
            case kOffData: {
                auto* slave = emu_.TryGet<Pr31x00SpiSlave>();
                if (!slave) {
                    HaltUnsupportedAccess("PR31x00 SPI TXDATA write with no slave on the bus", addr, value);
                }
                slave->SpiTxByte(static_cast<uint8_t>(value & 0xFFu));
                return;
            }

            default:
                HaltUnsupportedAccess("PR31x00 SPI WriteWord", addr, value);
        }
    }

    uint8_t  ReadByte(uint32_t addr) override { HaltUnsupportedAccess("PR31x00 SPI ReadByte", addr, 0); }
    uint16_t ReadHalf(uint32_t addr) override { HaltUnsupportedAccess("PR31x00 SPI ReadHalf", addr, 0); }
    void WriteByte(uint32_t addr, uint8_t  v) override { HaltUnsupportedAccess("PR31x00 SPI WriteByte", addr, v); }
    void WriteHalf(uint32_t addr, uint16_t v) override { HaltUnsupportedAccess("PR31x00 SPI WriteHalf", addr, v); }

    void SaveState(StateWriter& w) override {
        w.Write("ctl", ctl_);
        if (auto* slave = emu_.TryGet<Pr31x00SpiSlave>()) slave->SaveState(w);
    }
    void RestoreState(StateReader& r) override {
        r.Read("ctl", ctl_);
        if (auto* slave = emu_.TryGet<Pr31x00SpiSlave>()) slave->RestoreState(r);
    }

private:
    /* Every writable field resets to 0 (§14.3.1); DELAYVAL and BAUDRATE reset
       undefined and are taken as 0. */
    uint32_t ctl_ = 0x00000000u;
};

}  /* namespace */

REGISTER_SERVICE(Pr31x00Spi);
