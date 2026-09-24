#include "vrc4172_gpio.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../boards/nec_mobilepro_700/nec_mobilepro_700_id.h"
#include "../peripheral_dispatcher.h"
#include "../../socs/vr41xx/vr41xx_giu.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

constexpr uint32_t kBase = 0x15001080u;

/* Bank-0 register offsets (NetBSD vrc4172gpioreg.h). */
constexpr uint32_t kData0   = 0x00u;   /* EXGPDATA0   I/O pin data (0..15) */
constexpr uint32_t kDir0    = 0x02u;   /* EXGPDIR0    direction (1=out, 0=in) */
constexpr uint32_t kInten0  = 0x04u;   /* EXGPINTEN0  per-pin interrupt enable */
constexpr uint32_t kIntst0  = 0x06u;   /* EXGPINTST0  per-pin interrupt status (W1C) */
constexpr uint32_t kInttyp0 = 0x08u;   /* EXGPINTTYP0 interrupt type (1=edge, 0=level) */

/* Which VR4102 GIU pin the VRC4172's aggregate INT output is wired to. Changing
   this misroutes the interrupt: the guest's ICU decode (nk.exe sub_9F002050)
   sub-decodes this block only under GIU pin 1, and sub_9F002B94 arms GIU pin 1
   (GIUINTENL bit1) level/active-high - a different pin never reaches the ISR. */
constexpr int kGiuIntPin = 1;

}  /* namespace */

REGISTER_SERVICE(Vrc4172Gpio);

bool Vrc4172Gpio::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::NecMobilepro700;
}
void Vrc4172Gpio::OnReady() { emu_.Get<PeripheralDispatcher>().Register(this); }

/* The CE 2.0 OAL accesses this block with byte (lbu/sb) and halfword (lh/sh) ops
   (the 16-bit ISA bus); 32-bit access is NetBSD-driver-only -> FATAL. */
uint8_t Vrc4172Gpio::ReadByte(uint32_t addr) {
    const uint32_t off = addr - kBase;
    if (off & 1u) HaltUnsupportedAccess("VRC4172 GPIO ReadByte (odd offset)", addr, 0);
    std::lock_guard<std::mutex> lk(mtx_);
    return static_cast<uint8_t>(ReadReg16Locked(off) & 0xFFu);
}
uint16_t Vrc4172Gpio::ReadHalf(uint32_t addr) {
    std::lock_guard<std::mutex> lk(mtx_);
    return ReadReg16Locked(addr - kBase);
}

void Vrc4172Gpio::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = addr - kBase;
    if (off & 1u) HaltUnsupportedAccess("VRC4172 GPIO WriteByte (odd offset)", addr, value);
    std::lock_guard<std::mutex> lk(mtx_);
    /* Byte write drives only the low lane of the 16-bit register (16-bit ISA bus);
       preserve pins 8-15 in the high byte. */
    switch (off) {
        case kDir0:    dir_    = static_cast<uint16_t>((dir_    & 0xFF00u) | value); return;
        case kInttyp0: inttyp_ = static_cast<uint16_t>((inttyp_ & 0xFF00u) | value); return;
        case kInten0:  inten_  = static_cast<uint16_t>((inten_  & 0xFF00u) | value); DriveGiuLocked(); return;
        case kIntst0:  intst_ &= ~static_cast<uint16_t>(value); DriveGiuLocked(); return;  /* W1C low lane */
        default:       HaltUnsupportedAccess("VRC4172 GPIO WriteByte", kBase + off, value);
    }
}
void Vrc4172Gpio::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - kBase;
    std::lock_guard<std::mutex> lk(mtx_);
    switch (off) {
        case kDir0:    dir_    = value; return;
        case kInttyp0: inttyp_ = value; return;
        case kInten0:  inten_  = value; DriveGiuLocked(); return;
        case kIntst0:  intst_ &= ~value; DriveGiuLocked(); return;   /* W1C */
        default:       HaltUnsupportedAccess("VRC4172 GPIO WriteHalf", kBase + off, value);
    }
}

uint16_t Vrc4172Gpio::ReadReg16Locked(uint32_t off) {
    switch (off) {
        case kData0:   return static_cast<uint16_t>(level_ & ~dir_);  /* input pins reflect pin level */
        case kDir0:    return dir_;
        case kInten0:  return inten_;
        case kIntst0:  return intst_;
        case kInttyp0: return inttyp_;
        default:       HaltUnsupportedAccess("VRC4172 GPIO ReadHalf", kBase + off, 0);
    }
}

void Vrc4172Gpio::SetPinLevel(int pin, bool level) {
    if (pin < 0 || pin > 15) {
        LOG(Caution, "Vrc4172Gpio::SetPinLevel: pin %d outside modeled bank-0 "
                     "[15:0] (bank-1 pins 16-23 not modeled)\n", pin);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    std::lock_guard<std::mutex> lk(mtx_);

    const uint16_t bit  = static_cast<uint16_t>(1u << pin);
    const bool     prev = (level_ & bit) != 0;
    if (level) level_ |= bit; else level_ &= ~bit;

    if (inten_ & bit) {
        /* Polarity select lives in INTLV0L (pins 0-7) / INTLV0H (pins 8-15): the
           low-byte bit selects pos-edge / active-high, the high-byte bit selects
           both-edge (NetBSD vrc4172gpio_intr_dump). */
        const uint16_t intlv = (pin < 8) ? intlv0l_ : intlv0h_;
        const uint16_t m2    = static_cast<uint16_t>(1u << (pin & 7));
        if (inttyp_ & bit) {                                   /* edge */
            bool fired;
            if (intlv & (m2 << 8)) fired = (prev != level);    /* both edges */
            else if (intlv & m2)   fired = (!prev && level);   /* positive edge */
            else                   fired = (prev && !level);   /* negative edge */
            if (fired) intst_ |= bit;                          /* latch until W1C */
        } else {                                               /* level */
            const bool active = (level == ((intlv & m2) != 0));
            if (active) intst_ |= bit; else intst_ &= ~bit;    /* follows input (no hold reg) */
        }
    }
    DriveGiuLocked();
}

void Vrc4172Gpio::DriveGiuLocked() {
    const bool asserted = (intst_ & inten_) != 0;
    if (asserted == giu_asserted_) return;
    giu_asserted_ = asserted;
    emu_.Get<Vr41xxGiu>().SetPinLevel(kGiuIntPin, asserted);
}

void Vrc4172Gpio::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mtx_);
    w.Write("dir", dir_); w.Write("inten", inten_); w.Write("intst", intst_); w.Write("inttyp", inttyp_);
    w.Write("intlv0l", intlv0l_); w.Write("intlv0h", intlv0h_); w.Write("level", level_);
}
void Vrc4172Gpio::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    r.Read("dir", dir_); r.Read("inten", inten_); r.Read("intst", intst_); r.Read("inttyp", inttyp_);
    r.Read("intlv0l", intlv0l_); r.Read("intlv0h", intlv0h_); r.Read("level", level_);
}
void Vrc4172Gpio::PostRestore() {
    std::lock_guard<std::mutex> lk(mtx_);
    giu_asserted_ = (intst_ & inten_) != 0;
    emu_.Get<Vr41xxGiu>().SetPinLevel(kGiuIntPin, giu_asserted_);
}
