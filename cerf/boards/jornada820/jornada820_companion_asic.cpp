#include "jornada820_companion_asic.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "jornada_820_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../socs/sa11xx/sa11xx_gpio.h"
#include "../../state/state_stream.h"
#include "jornada820_pcmcia.h"

namespace {
/* GlidePad IRQ = SA-1100 GPIO14: runtime-proven the only edge GPIO whose pulse
   wakes glidepad.dll's InterruptInitialize(29) thread sub_12B1EFC. Other values
   (e.g. GPIO1, masked in ICMR) never deliver and the touchpad goes dead. */
constexpr uint32_t kGpio = 14u;
}  /* namespace */

bool Jornada820CompanionAsic::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Jornada820;
}

void Jornada820CompanionAsic::OnReady() {
    store_.assign(MmioSize(), 0u);
    emu_.Get<PeripheralDispatcher>().Register(this);
    /* The deep-sleep wake (and any reset) leaves the GlidePad PS/2 controller
       clean on hardware; the guest re-inits it with F6+F4 (no FF reset), so flush
       any queued pre-suspend motion that would otherwise sit ahead of the F6 ACK
       and desync the re-init handshake. */
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) { mouse_.Reset(); });
}

uint8_t Jornada820CompanionAsic::ReadByte(uint32_t addr) {
    const uint32_t o = addr - MmioBase();
    if (o == kPs2Status) return Ps2StatusByte();
    if (o == kPs2Data)   return mouse_.ReadData();
    return store_[o];
}

uint16_t Jornada820CompanionAsic::ReadHalf(uint32_t addr) {
    const uint32_t o = addr - MmioBase();
    return cerf::le::U16(store_.data(), o);
}

uint32_t Jornada820CompanionAsic::ReadWord(uint32_t addr) {
    const uint32_t o = addr - MmioBase();
    if (o == kPs2Status)     return Ps2StatusByte();
    if (o == kPs2Data)       return mouse_.ReadData();
    if (o == kPcmciaStatus)  return emu_.Get<Jornada820Pcmcia>().ReadSocketStatus();
    if (o == kIntrStatus)    return intr_pending_;
    return cerf::le::U32(store_.data(), o);
}

void Jornada820CompanionAsic::WriteByte(uint32_t addr, uint8_t v) {
    const uint32_t o = addr - MmioBase();
    if (o == kPs2Data) { mouse_.WriteCommand(v); return; }
    store_[o] = v;
}

void Jornada820CompanionAsic::WriteHalf(uint32_t addr, uint16_t v) {
    cerf::le::Put16(store_.data() + (addr - MmioBase()), v);
}

void Jornada820CompanionAsic::WriteWord(uint32_t addr, uint32_t v) {
    const uint32_t o = addr - MmioBase();
    if (o == kPs2Data) { mouse_.WriteCommand(static_cast<uint8_t>(v)); return; }
    if (o == kIntrStatus) {            /* W1C: written 1-bits clear pending */
        intr_pending_ &= ~v;
        if (intr_pending_ & IntrMask()) PulseGpio14();  /* another source waits */
        return;
    }
    cerf::le::Put32(store_.data() + o, v);
}

void Jornada820CompanionAsic::PulseGpio14() {
    auto& gpio = emu_.Get<Sa11xxGpio>();
    gpio.DriveInputPin(kGpio, false);
    gpio.DriveInputPin(kGpio, true);   /* rising edge -> GEDR / INTC source 11 */
}

void Jornada820CompanionAsic::RaiseIntrSource(uint32_t bit) {
    if ((IntrMask() & bit) == 0u) return;   /* source disabled in the OAL mask */
    intr_pending_ |= bit;
    PulseGpio14();
}

void Jornada820CompanionAsic::RaiseIrq() { RaiseIntrSource(kSrcMouse); }

void Jornada820CompanionAsic::RaisePcmciaCardIrq(int socket) {
    RaiseIntrSource(socket == 0 ? kSrcCard0 : kSrcCard1);
}

void Jornada820CompanionAsic::RaisePcmciaStatusChange(int socket) {
    RaiseIntrSource(socket == 0 ? kSrcStat0 : kSrcStat1);
}

void Jornada820CompanionAsic::SaveState(StateWriter& w) {
    w.Write<uint64_t>(store_.size());
    w.WriteBytes(store_.data(), store_.size());
    w.Write(intr_pending_);
    mouse_.SaveState(w);
}

void Jornada820CompanionAsic::RestoreState(StateReader& r) {
    uint64_t n = 0;
    r.Read(n);
    store_.assign(static_cast<size_t>(n), 0u);
    r.ReadBytes(store_.data(), static_cast<size_t>(n));
    r.Read(intr_pending_);
    mouse_.RestoreState(r);
}

REGISTER_SERVICE(Jornada820CompanionAsic);
