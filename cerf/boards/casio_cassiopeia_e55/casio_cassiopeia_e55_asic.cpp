#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../state/state_stream.h"
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

/* casio_cassiopeia_e55 pcmcia.dll sub_14C0E8C (+0x02 |= 1, +0x00 |= 1, +0x02 &= ~1,
   +0x00 |= 2), sub_14C1078 (+0x00 = 0 / = 12, +0x06 &= ~1 / |= 1), sub_14C096C and
   sub_14C0A70 (+0x02 |= 2 / &= ~2, +0x00 &= ~4 / |= 4). */
constexpr uint32_t kOffCtrl0 = 0x000u;
constexpr uint32_t kOffCtrl2 = 0x002u;
constexpr uint32_t kOffCtrl6 = 0x006u;
constexpr uint16_t kCtrl0Writable = 0x000Fu;
constexpr uint16_t kCtrl2Writable = 0x0003u;
constexpr uint16_t kCtrl6Writable = 0x0001u;

/* casio_cassiopeia_e55 pcmcia.dll: sub_14C0E8C no-card arm on (+0x04 & 6) != 0, poll exit
   on (+0x04 & 1); sub_14C0B84 card-detect on (+0x04 & 6) == 0. */
constexpr uint32_t kOffStatus = 0x004u;
constexpr uint16_t kStatusNoCard = 0x000Eu;

/* casio_cassiopeia_e55 pcmcia.dll sub_14C0728 zeroes +0x0A @0x14C08AC, +0x0C @0x14C08B4,
   +0x08 @0x14C08C0; no function with an xref to the mapped base reads them. */
constexpr uint32_t kOffInit08 = 0x008u;
constexpr uint32_t kOffInit0A = 0x00Au;
constexpr uint32_t kOffInit0C = 0x00Cu;

/* casio_cassiopeia_e55 pcmcia.dll sub_14C096C / sub_14C0A70 save +0x14, set its D0 for
   the card access and restore the saved value; sub_14C14C0 clears or sets the same bit
   per socket. D2:1 are the read-only strap. */
constexpr uint16_t kStrapWritable = 0x0001u;

class CasioCassiopeiaE55Asic : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::CasioCassiopeiaE55;
    }

    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            ctrl0_ = 0u;
            ctrl2_ = 0u;
            ctrl6_ = 0u;
            card_access_ = 0u;
        });
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint16_t ReadHalf(uint32_t addr) override {
        switch (addr - kBase) {
            case kOffCtrl0:      return ctrl0_;
            case kOffCtrl2:      return ctrl2_;
            case kOffStatus:     return kStatusNoCard;
            case kOffCtrl6:      return ctrl6_;
            case kOffButtons:    return kButtonsAllReleased;
            case kOffVdet:       return kNoVdetEvent;
            case kOffStrap:      return static_cast<uint16_t>(kStrapValue | card_access_);
            default: return Peripheral::ReadHalf(addr);
        }
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        switch (addr - kBase) {
            case kOffCtrl0: ctrl0_ = Accept(addr, value, kCtrl0Writable); return;
            case kOffCtrl2: ctrl2_ = Accept(addr, value, kCtrl2Writable); return;
            case kOffCtrl6: ctrl6_ = Accept(addr, value, kCtrl6Writable); return;
            case kOffInit08:
            case kOffInit0A:
            case kOffInit0C:
            case kOffReg0E:
                if (value != 0u) HaltUnsupportedAccess("WriteHalf", addr, value);
                return;
            case kOffStrap:
                if ((value & kStrapValue) != kStrapValue) {
                    HaltUnsupportedAccess("WriteHalf clears the strap", addr, value);
                }
                card_access_ = Accept(addr, value, kStrapWritable | kStrapValue) & kStrapWritable;
                return;
            default: Peripheral::WriteHalf(addr, value); return;
        }
    }

    void SaveState(StateWriter& w) override {
        w.Write(ctrl0_); w.Write(ctrl2_); w.Write(ctrl6_); w.Write(card_access_);
    }
    void RestoreState(StateReader& r) override {
        r.Read(ctrl0_); r.Read(ctrl2_); r.Read(ctrl6_); r.Read(card_access_);
    }

private:
    uint16_t Accept(uint32_t addr, uint16_t value, uint16_t writable) {
        if ((value & ~writable) != 0u) HaltUnsupportedAccess("WriteHalf", addr, value);
        return value;
    }

    uint16_t ctrl0_ = 0u;
    uint16_t ctrl2_ = 0u;
    uint16_t ctrl6_ = 0u;
    uint16_t card_access_ = 0u;
};

}  /* namespace */

REGISTER_SERVICE(CasioCassiopeiaE55Asic);
