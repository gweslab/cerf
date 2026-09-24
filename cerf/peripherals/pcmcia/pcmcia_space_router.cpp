#include "pcmcia_space_router.h"

#include "../../boards/board_context.h"
#include "../../socs/sa11xx/sa1110_id.h"
#include "../../socs/pxa255/pxa255_id.h"
#include "../../socs/sa11xx/sa1100_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "pcmcia_slot.h"
#include "../peripheral_dispatcher.h"
#include "../../state/state_stream.h"

namespace {

constexpr uint8_t  kFloat8  = 0xFFu;
constexpr uint16_t kFloat16 = 0xFFFFu;

}  /* namespace */

bool PcmciaSpaceRouter::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    if (!bd) return false;
    const std::string_view soc = bd->GetSocId();
    return soc == SocId::Sa1110 || soc == SocId::Pxa255 ||
           soc == SocId::Sa1100;
}

void PcmciaSpaceRouter::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void PcmciaSpaceRouter::ProvideSockets(PcmciaSlot* socket0,
                                       PcmciaSlot* socket1) {
    sockets_[0] = socket0;
    sockets_[1] = socket1;
}

PcmciaSlot* PcmciaSpaceRouter::Socket(int n) const {
    return (n == 0 || n == 1) ? sockets_[n] : nullptr;
}

void PcmciaSpaceRouter::SaveState(StateWriter& w) {
    for (int i = 0; i < 2; ++i) {
        PcmciaSlot* s = sockets_[i];
        w.Write<uint8_t>("socket_present", s ? 1u : 0u);
        if (s) s->SaveSlotState(w);
    }
}

void PcmciaSpaceRouter::RestoreState(StateReader& r) {
    for (int i = 0; i < 2; ++i) {
        uint8_t present = 0; r.Read("socket_present", present);
        if ((present != 0u) != (sockets_[i] != nullptr))
            r.Reject("socket %d is %s in the image and %s in this build", i,
                     present ? "wired" : "absent", sockets_[i] ? "wired" : "absent");
        if (sockets_[i]) sockets_[i]->RestoreSlotState(r);
    }
}

void PcmciaSpaceRouter::PostRestore() {
    for (PcmciaSlot* s : sockets_)
        if (s) s->PostRestoreSlot();
}

PcmciaSlot* PcmciaSpaceRouter::Decode(uint32_t addr, Region* region,
                                      uint32_t* card_offset) const {
    const uint32_t off    = addr - MmioBase();
    const int      socket = (off >> 28) & 1;             /* 256 MB per socket */
    *region      = static_cast<Region>((off >> 26) & 3); /* 64 MB sub-regions */
    *card_offset = off & 0x03FFFFFFu;
    return sockets_[socket];
}

uint8_t PcmciaSpaceRouter::ReadByte(uint32_t addr) {
    Region region;
    uint32_t off;
    PcmciaSlot* slot = Decode(addr, &region, &off);
    if (!slot) return kFloat8;
    switch (region) {
        case Region::Io:        return slot->ReadIo8(off);
        case Region::Attribute: return slot->ReadAttribute8(off);
        case Region::Common:    return slot->ReadCommon8(off);
        case Region::Reserved:  break;
    }
    LOG(Pcmcia, "[PCMCIA] read8 in reserved band PA 0x%08X\n", addr);
    return kFloat8;
}

uint16_t PcmciaSpaceRouter::ReadHalf(uint32_t addr) {
    Region region;
    uint32_t off;
    PcmciaSlot* slot = Decode(addr, &region, &off);
    if (!slot) return kFloat16;
    switch (region) {
        case Region::Io:        return slot->ReadIo16(off);
        case Region::Attribute: {
            /* Attribute memory drives even bytes only; the even byte
               images on both halves of the 16-bit bus. */
            const uint8_t v = slot->ReadAttribute8(off & ~1u);
            return static_cast<uint16_t>((v << 8) | v);
        }
        case Region::Common:    return slot->ReadCommon16(off);
        case Region::Reserved:  break;
    }
    LOG(Pcmcia, "[PCMCIA] read16 in reserved band PA 0x%08X\n", addr);
    return kFloat16;
}

uint32_t PcmciaSpaceRouter::ReadWord(uint32_t addr) {
    /* 16-bit PC Card bus: a 32-bit access is two halfword cycles. */
    const uint32_t lo = ReadHalf(addr);
    const uint32_t hi = ReadHalf(addr + 2u);
    return lo | (hi << 16);
}

void PcmciaSpaceRouter::WriteByte(uint32_t addr, uint8_t value) {
    Region region;
    uint32_t off;
    PcmciaSlot* slot = Decode(addr, &region, &off);
    if (!slot) return;
    switch (region) {
        case Region::Io:        slot->WriteIo8(off, value);        return;
        case Region::Attribute: slot->WriteAttribute8(off, value); return;
        case Region::Common:    slot->WriteCommon8(off, value);    return;
        case Region::Reserved:  break;
    }
    LOG(Pcmcia, "[PCMCIA] write8 in reserved band PA 0x%08X = 0x%02X\n",
        addr, value);
}

void PcmciaSpaceRouter::WriteHalf(uint32_t addr, uint16_t value) {
    Region region;
    uint32_t off;
    PcmciaSlot* slot = Decode(addr, &region, &off);
    if (!slot) return;
    switch (region) {
        case Region::Io:        slot->WriteIo16(off, value); return;
        case Region::Attribute:
            /* Even byte carries the attribute data on a 16-bit write. */
            slot->WriteAttribute8(off & ~1u,
                                  static_cast<uint8_t>(value & 0xFFu));
            return;
        case Region::Common:    slot->WriteCommon16(off, value); return;
        case Region::Reserved:  break;
    }
    LOG(Pcmcia, "[PCMCIA] write16 in reserved band PA 0x%08X = 0x%04X\n",
        addr, value);
}

void PcmciaSpaceRouter::WriteWord(uint32_t addr, uint32_t value) {
    WriteHalf(addr,      static_cast<uint16_t>(value & 0xFFFFu));
    WriteHalf(addr + 2u, static_cast<uint16_t>(value >> 16));
}

REGISTER_SERVICE(PcmciaSpaceRouter);
