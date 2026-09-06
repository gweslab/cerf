#include "../../peripherals/open_bus_window.h"

#include "../../core/cerf_emulator.h"

namespace {

/* VR4111 UM Table 6-7 printed p.167 and Table 6-8 p.168: PA 0x1E000000-0x1E7FFFFF
   is a ROMCS bank in every column that also maps 0x1E800000, where
   casio_cassiopeia_e55 nk.bin ROMHDR physfirst 0x9E800000 puts the CE XIP. Which
   bank number is not readable from the ROM, since the column is selected by the
   DBUS32 pin. casio_cassiopeia_e55 dic2.dll DicAlloc @0x13D0CE4 VirtualCopy's this
   exact extent at KSEG1 0xBE000000; that image carries none of its bytes. */
class CasioCassiopeiaE55RomOpenBus : public OpenBusWindow {
public:
    using OpenBusWindow::OpenBusWindow;

    uint32_t MmioBase() const override { return 0x1E000000u; }
    uint32_t MmioSize() const override { return 0x00800000u; }

protected:
    Board       WindowBoard() const override { return Board::CasioCassiopeiaE55; }
    const char* WindowTag()   const override { return "E55 dictionary ROM"; }
};

}  /* namespace */

REGISTER_SERVICE(CasioCassiopeiaE55RomOpenBus);
