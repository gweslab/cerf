#include "philips_velo_1_keyboard_ec.h"

#include "../board_context.h"
#include "philips_velo_1_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../host/guest_deep_sleep.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../socs/pr31x00/pr31x00_intc.h"
#include "../../state/state_stream.h"

namespace {

/* SPIRCVINT is Interrupt Status 5 bit 19 (R3912.H INTR_SPIRCVINT under
   OFF_INTR_STATUS5). Status 5 is INTC set index 4. */
constexpr uint32_t kStatus5Set = 4;
constexpr uint32_t kSpiRcvInt  = 1u << 19;

/* The framed enable packet keybddr's sub_1F3CF14 recognises: header 0x80, command
   0xA8, a zero, a byte, then the checksum (serial.dll sub_1EBD2FC: XOR the bytes,
   fold with ^0xC0 if bit 7 set). Its sub_1F3CD00 handler runs sub_1F3C8B4, which
   sets dword_1F40010=2 - the state sub_1F3D014 requires before it queues a key. */
constexpr uint8_t kPktHeader = 0x80;
constexpr uint8_t kPktCmd    = 0xA8;
constexpr uint8_t kPktZero   = 0x00;

uint8_t ScanChecksum(uint8_t b) {
    const uint8_t v = kPktHeader ^ kPktCmd ^ kPktZero ^ b;
    return (v & 0x80) ? static_cast<uint8_t>(v ^ 0xC0) : v;
}

}  // namespace

bool PhilipsVelo1KeyboardEc::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::PhilipsVelo1;
}

void PhilipsVelo1KeyboardEc::OnReady() {
    /* A real keyboard controller hands off its scan/enable packet when the host
       arms the SPI receive interrupt; do the same when serial.dll unmasks SPIRCVINT
       (sub_1EBD1F0 sets Enable5 bit 19). keybddr's enable (sub_1F3C8B4) then posts
       the 0x10000 layout event gwes needs to allocate its keyboard-layout buffer. */
    emu_.Get<Pr31x00Intc>().RegisterEnableListener(
        kStatus5Set, kSpiRcvInt, [this] { OnSpiRcvIntEnabled(); });

    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) { Unhandshake(); });

    emu_.Get<GuestDeepSleep>().RegisterPowerUpListener([this] { Unhandshake(); });
}

void PhilipsVelo1KeyboardEc::Unhandshake() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        enabled_ = false;
        tx_.clear();
    }
    emu_.Get<Pr31x00Intc>().ClearPending(kStatus5Set, kSpiRcvInt);
}

void PhilipsVelo1KeyboardEc::StageEnableLocked() {
    if (enabled_) return;
    /* The framed 0xA8 packet enables the keyboard (sub_1F3CD00 -> sub_1F3C8B4); its 4th
       byte selects sub_1F3CB98's enable-setup branch, so it must be 0. */
    tx_.push_back(kPktHeader);
    tx_.push_back(kPktCmd);
    tx_.push_back(kPktZero);
    tx_.push_back(0x00);
    tx_.push_back(ScanChecksum(0x00));
    enabled_ = true;
}

void PhilipsVelo1KeyboardEc::OnSpiRcvIntEnabled() {
    bool pending;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        StageEnableLocked();
        pending = !tx_.empty();
    }
    /* sub_1EBD1F0 writes Clear5 between two Enable5 unmasks, wiping the first unmask's
       assert; re-asserting while bytes remain lets the last unmask deliver the
       handshake, and nothing is asserted once the packet has drained. */
    if (pending) emu_.Get<Pr31x00Intc>().SetPending(kStatus5Set, kSpiRcvInt);
}

void PhilipsVelo1KeyboardEc::InjectKey(uint8_t scancode, bool key_up) {
    LOG(Trace, "[VELOKEY] InjectKey scancode=0x%02X up=%d\n", scancode, key_up ? 1 : 0);
    const uint8_t sc = key_up ? static_cast<uint8_t>(scancode | 0x80) : scancode;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        StageEnableLocked();   /* fallback if a key arrives before the boot handshake */
        tx_.push_back(sc);
    }
    /* serial.dll's SPI IST (sub_1EBD354) reads one byte per SPIRCVINT: sub_1EBD514
       clears the interrupt then reads RXDATA, so each staged byte gets its own
       SPIRCVINT (re-raised in SpiRxReadByte while bytes remain). */
    emu_.Get<Pr31x00Intc>().SetPending(kStatus5Set, kSpiRcvInt);
}

bool PhilipsVelo1KeyboardEc::SpiRxHasByte() {
    std::lock_guard<std::mutex> lk(mtx_);
    return !tx_.empty();
}

uint8_t PhilipsVelo1KeyboardEc::SpiRxReadByte() {
    uint8_t b;
    bool more;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        b = tx_.front();
        tx_.pop_front();
        more = !tx_.empty();
    }
    if (more) {
        emu_.Get<Pr31x00Intc>().SetPending(kStatus5Set, kSpiRcvInt);
    }
    return b;
}

/* keybddr configures the EC's own key scan/auto-repeat via command bytes
   (sub_1F3C8B4's [0x1B,0xA6,0x02,...] typematic stream, sent on every scan packet).
   CERF injects keys from the host, so there is nothing to configure and the send
   path reads no reply. FATAL here would crash on the next key (sub_1F3CD00). */
void PhilipsVelo1KeyboardEc::SpiTxByte(uint8_t /*byte*/) {}

void PhilipsVelo1KeyboardEc::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mtx_);
    w.Write("enabled", enabled_);
    const uint32_t n = static_cast<uint32_t>(tx_.size());
    w.Write("tx_count", n);
    for (uint8_t b : tx_) w.Write("tx", b);
}

void PhilipsVelo1KeyboardEc::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    r.Read("enabled", enabled_);
    tx_.clear();
    uint32_t n = 0;
    r.Read("tx_count", n);
    for (uint32_t i = 0; i < n; ++i) {
        uint8_t b = 0;
        r.Read("tx", b);
        tx_.push_back(b);
    }
}

REGISTER_SERVICE_AS(PhilipsVelo1KeyboardEc, Pr31x00SpiSlave);
