#include "../../peripherals/ite_it8368/ite_it8368_bus_window.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "philips_velo_1_id.h"

#include <cstdint>

namespace {

/* The M-Module's IT8368E sits on chip select 2, PA $1040_0000 (Table 4.2.1,
   TMPR3911.pdf PDF p.104). pcmcia.dll sub_1F113A0 VirtualCopies $24 bytes of it. */
constexpr uint32_t kBase = 0x10400000u;
constexpr uint32_t kSize = 0x24u;

/* $22 is past the IT8368E's last register (it8368reg.h stops at IT8368_CTRL_REG
   $20): it is the M-Module's own ID. nk.exe sub_9F40F688 programs the socket only
   when (id & 0xFF00) == 0x4900, and nk.1.exe sub_9FB11194 needs exactly 0x4900. */
constexpr uint32_t kOffModuleId = 0x22u;
constexpr uint16_t kIcebergId   = 0x4900u;

class PhilipsVelo1SocketController : public IteIt8368BusWindow {
public:
    using IteIt8368BusWindow::IteIt8368BusWindow;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::PhilipsVelo1;
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint16_t ReadHalf(uint32_t addr) override {
        if (addr - kBase == kOffModuleId) return kIcebergId;
        return IteIt8368BusWindow::ReadHalf(addr);
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        if (addr - kBase == kOffModuleId) {
            HaltUnsupportedAccess("Velo 1 M-Module ID write", addr, value);
        }
        IteIt8368BusWindow::WriteHalf(addr, value);
    }

protected:
    /* This board does not cross the chip's byte lanes, so the halfword reaches the
       IT8368E in its own bit order: nk.exe sub_9F40F688 writes GPIODIR = $10F1,
       which is it8368.c:262-265's CRDVCC|CRDVPP|BCRDRST plus CRDSW. */
    bool LanesCrossed() const override { return false; }
};

}

REGISTER_SERVICE(PhilipsVelo1SocketController);
