#include "casio_cassiopeia_e55_pccard.h"

#include "../../core/cerf_emulator.h"
#include "../../host/host_widget_registry.h"
#include "../../peripherals/pcmcia/pcmcia_auto_insert.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../socs/vr41xx/vr41xx_giu.h"
#include "../../state/state_stream.h"
#include "../board_context.h"

namespace {

constexpr uint32_t kWindowBase = 0x1400E000u;
constexpr uint32_t kWindowSize = 0x800u;

/* casio_cassiopeia_e55 pcmcia.dll sub_14C0B84 @0x14C0B84 reports a card on
   (+0x04 & 6) == 0 and ready on (+0x04 & 1) != 0. */
constexpr uint16_t kStatusCardAbsent = 0x0006u;
constexpr uint16_t kStatusReady      = 0x0001u;

/* casio_cassiopeia_e55 pcmcia.dll sub_14C0B84 @0x14C0B84 turns a CLEAR +0x04 D3 into a set
   bit of its own status byte; no function of the module writes D3 or branches on that
   status bit. */
constexpr uint16_t kStatusD3 = 0x0008u;

/* casio_cassiopeia_e55 pcmcia.dll sub_14C0CAC @0x14C0CAC gates GIUINTENL D0 on the socket
   record's byte 5 bit 7 and masks D1 unconditionally; sub_14C1078 @0x14C1078 does the same.
   Both clear GIUINTALSELL D0, a low-active level input (PC Card Standard IREQ#). */
constexpr int kCardIreqGiuPin = 0;

}  /* namespace */

CasioCassiopeiaE55PcCard::CasioCassiopeiaE55PcCard(CerfEmulator& emu)
    : Peripheral(emu), slot0_(emu, *this, L"CompactFlash slot") {}

bool CasioCassiopeiaE55PcCard::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoard() == Board::CasioCassiopeiaE55;
}

void CasioCassiopeiaE55PcCard::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
    emu_.Get<HostWidgetRegistry>().Register(&slot0_);
    emu_.Get<Vr41xxGiu>().SetPinLevel(kCardIreqGiuPin, true);
    emu_.Get<PcmciaAutoInsert>().InsertLaunchCompactFlash(slot0_);
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        reg_space_ = false;
        in_reset_  = false;
        slot0_.SetPowered(false);
        emu_.Get<Vr41xxGiu>().SetPinLevel(kCardIreqGiuPin, true);
    });
}

void CasioCassiopeiaE55PcCard::OnShutdown() { slot0_.OnShutdown(); }

uint32_t CasioCassiopeiaE55PcCard::MmioBase() const { return kWindowBase; }
uint32_t CasioCassiopeiaE55PcCard::MmioSize() const { return kWindowSize; }

uint8_t CasioCassiopeiaE55PcCard::ReadByte(uint32_t addr) {
    const uint32_t off = addr - kWindowBase;
    if (reg_space_) return slot0_.ReadAttribute8(off);
    return slot0_.ReadCommon8(off);
}

void CasioCassiopeiaE55PcCard::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = addr - kWindowBase;
    if (reg_space_) { slot0_.WriteAttribute8(off, value); return; }
    slot0_.WriteCommon8(off, value);
}

uint16_t CasioCassiopeiaE55PcCard::ReadHalf(uint32_t addr) {
    if (reg_space_) return Peripheral::ReadHalf(addr);
    return slot0_.ReadCommon16(addr - kWindowBase);
}

void CasioCassiopeiaE55PcCard::WriteHalf(uint32_t addr, uint16_t value) {
    if (reg_space_) { Peripheral::WriteHalf(addr, value); return; }
    slot0_.WriteCommon16(addr - kWindowBase, value);
}

uint8_t  CasioCassiopeiaE55PcCard::ReadIo8 (uint32_t off) { return slot0_.ReadIo8(off); }
uint16_t CasioCassiopeiaE55PcCard::ReadIo16(uint32_t off) { return slot0_.ReadIo16(off); }
void CasioCassiopeiaE55PcCard::WriteIo8 (uint32_t off, uint8_t  v) { slot0_.WriteIo8(off, v); }
void CasioCassiopeiaE55PcCard::WriteIo16(uint32_t off, uint16_t v) { slot0_.WriteIo16(off, v); }

void CasioCassiopeiaE55PcCard::SetRegSpace(bool on) { reg_space_ = on; }

void CasioCassiopeiaE55PcCard::SetSocketPower(bool on) { slot0_.SetPowered(on); }

void CasioCassiopeiaE55PcCard::SetResetStrobe(bool on) {
    if (in_reset_ && !on) slot0_.ResetCard();
    in_reset_ = on;
}

uint16_t CasioCassiopeiaE55PcCard::StatusReg() const {
    uint16_t v = kStatusD3;
    if (!slot0_.HasCard()) v |= kStatusCardAbsent;
    if (slot0_.IsPowered() && !in_reset_) v |= kStatusReady;
    return v;
}

/* casio_cassiopeia_e55 pcmcia.dll sub_14C091C @0x14C091C starts sub_14C0658 @0x14C0658,
   which samples (+0x04 & 6) once a second and calls SetInterruptEvent(21) on a change. */
void CasioCassiopeiaE55PcCard::OnCardDetectChanged(PcmciaSlot&) {}

void CasioCassiopeiaE55PcCard::OnCardIrqAsserted(PcmciaSlot&) {
    emu_.Get<Vr41xxGiu>().SetPinLevel(kCardIreqGiuPin, false);
}

void CasioCassiopeiaE55PcCard::OnCardIrqDeasserted(PcmciaSlot&) {
    emu_.Get<Vr41xxGiu>().SetPinLevel(kCardIreqGiuPin, true);
}

void CasioCassiopeiaE55PcCard::SaveState(StateWriter& w) {
    w.Write(reg_space_);
    w.Write(in_reset_);
    slot0_.SaveSlotState(w);
}

void CasioCassiopeiaE55PcCard::RestoreState(StateReader& r) {
    r.Read(reg_space_);
    r.Read(in_reset_);
    slot0_.RestoreSlotState(r);
}

void CasioCassiopeiaE55PcCard::PostRestore() { slot0_.PostRestoreSlot(); }

REGISTER_SERVICE(CasioCassiopeiaE55PcCard);
