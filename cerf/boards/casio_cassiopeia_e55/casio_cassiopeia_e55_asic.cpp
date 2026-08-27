#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../board_context.h"

#include <cstdint>

namespace {

/* casio_cassiopeia_e55 keybddr.dll 0x14E1FA4 passes this base to sub_14E1EF8
   (VirtualAlloc + VirtualCopy) with size 0x800 at 0x14E1FB0; pcmcia.dll
   0x14C0758 maps the same base with size 0x18 at 0x14C0764. */
constexpr uint32_t kBase = 0x1400A000u;
constexpr uint32_t kSize = 0x800u;

constexpr uint32_t kOffStrap = 0x14u;

/* casio_cassiopeia_e55: D2 clear selects the GIU status source (nk.exe sub_9E814EA8
   @0x9E814EC4, gwes.exe sub_AC2B8 @0xAC2E8). D1 set selects GIUIOSELH 0x1FC0 (nk.exe
   sub_9E816964 @0x9E8169F8, the mask sub_9E8144D4 @0x9E814508 writes at cold boot) and
   the 0xB400E000 card window (pcmcia.dll sub_14C1604). D0: pcmcia.dll 0x14C1524/38. */
constexpr uint16_t kStrapValue = 0x0002u;

constexpr uint32_t kOffButtons = 0x10u;

/* casio_cassiopeia_e55 nk.exe sub_9E8144D4 @0x9E814640 latches (+0x10 & 0xFF) into 0xA000251C.
   keybddr.dll sub_14E37C4 emits a key for each of bits 0/1/2 found CLEAR - codes 195/194/196,
   the 195/196 that sub_14E2028 writes as the ButtonA/ButtonB registry defaults - so a clear bit
   is a pressed button; nk.exe @0x9E814BA0 (ori $t1, 0xF) forces all four to released. */
constexpr uint16_t kButtonsAllReleased = 0x000Fu;

constexpr uint32_t kOffVdet = 0x12u;

/* casio_cassiopeia_e55 nk.exe sub_9E8144D4 @0x9E814A88 and @0x9E814BB0 mask +0x12 to bits 1:0;
   on == 3 they set 0xA0002520 = 1 and clear 0xA000254C, whose bit 0 makes keybddr.dll
   sub_14E37C4 @0x14E3D94 signal "VDETMessageEvent" (created @0x14E1D50, driver \Windows\kddrvdet
   @0x14E1DA8); nk.exe @0x9E817A44 (in no IDA function) sets it entering hibernate. 3 = no event. */
constexpr uint16_t kNoVdetEvent = 0x0003u;

/* casio_cassiopeia_e55 nk.exe sub_9E816964 @0x9E816A30 lui $t0, 0xB401 /
   @0x9E816A34 sh $zero, 0xB400A00E. */
constexpr uint32_t kOffReg0E = 0x00Eu;

class CasioCassiopeiaE55Asic : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::CasioCassiopeiaE55;
    }

    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint16_t ReadHalf(uint32_t addr) override {
        switch (addr - kBase) {
            case kOffButtons:    return kButtonsAllReleased;
            case kOffVdet:       return kNoVdetEvent;
            case kOffStrap:      return kStrapValue;
            default: return Peripheral::ReadHalf(addr);
        }
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        if (addr - kBase == kOffReg0E) {
            if (value != 0u) HaltUnsupportedAccess("WriteHalf", addr, value);
            return;
        }
        Peripheral::WriteHalf(addr, value);
    }
};

}  /* namespace */

REGISTER_SERVICE(CasioCassiopeiaE55Asic);
