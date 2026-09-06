#include "ipaq_gen1_egpio.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "ipaq_gen1_egpio_sink.h"

bool IpaqGen1Egpio::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoard() == Board::IpaqGen1;
}

void IpaqGen1Egpio::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void IpaqGen1Egpio::NotifySink() {
    if (auto* sink = emu_.TryGet<IpaqGen1EgpioSink>()) {
        sink->OnEgpioChanged(latched_.load(std::memory_order_acquire));
    }
}

void IpaqGen1Egpio::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = addr - MmioBase();
    if (off > 1u) HaltUnsupportedAccess("WriteByte", addr, value);
    const uint32_t shift  = 8u * off;
    const uint16_t mask   = static_cast<uint16_t>(0xFFu << shift);
    const uint16_t before = latched_.load(std::memory_order_acquire);
    const uint16_t after  =
        static_cast<uint16_t>((before & ~mask) | (static_cast<uint32_t>(value) << shift));
    latched_.store(after, std::memory_order_release);
    LOG(Periph, "[IpaqGen1Egpio] W8 +%u = 0x%02X -> latch 0x%04X (audio amp %s)\n",
        off, value, after, (after & kAudioOutputEnable) ? "powered" : "off");
    NotifySink();
}

/* Halfword store of a uint16_t shadow: NetBSD
   sys/arch/hpcarm/dev/ipaq_saip.c ipaq_attach. */
void IpaqGen1Egpio::WriteHalf(uint32_t addr, uint16_t value) {
    StoreLatch("WriteHalf", addr, value);
}

void IpaqGen1Egpio::WriteWord(uint32_t addr, uint32_t value) {
    StoreLatch("WriteWord", addr, value);
}

void IpaqGen1Egpio::StoreLatch(const char* op, uint32_t addr, uint32_t value) {
    if (addr != MmioBase()) HaltUnsupportedAccess(op, addr, value);
    const uint16_t latched = static_cast<uint16_t>(value);
    latched_.store(latched, std::memory_order_release);
    LOG(Periph, "[IpaqGen1Egpio] %s = 0x%04X (audio amp %s)\n",
        op, latched, (latched & kAudioOutputEnable) ? "powered" : "off");
    NotifySink();
}

void IpaqGen1Egpio::SaveState(StateWriter& w) {
    w.Write(latched_.load(std::memory_order_acquire));
}

void IpaqGen1Egpio::RestoreState(StateReader& r) {
    uint16_t v = 0;
    r.Read(v);
    latched_.store(v, std::memory_order_release);
}

REGISTER_SERVICE(IpaqGen1Egpio);
