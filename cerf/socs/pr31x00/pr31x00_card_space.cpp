#include "pr31x00_card_space.h"

#include "../../boards/board_context.h"
#include "pr31500_id.h"
#include "pr31700_id.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/pcmcia/pcmcia_slot.h"
#include "../../state/state_stream.h"
#include "pr31x00_biu.h"

namespace {

constexpr uint8_t  kFloat8  = 0xFFu;
constexpr uint16_t kFloat16 = 0xFFFFu;

constexpr uint32_t kCardShift   = 26;          /* 64 MB per card window */
constexpr uint32_t kCtrlOffMask = 0x03FFFFFFu;

/* A fixed-attribute buffer splits a card's 64 MB I/O-or-Attribute window in half
   and puts attribute space in the upper half (it8368.c:286-288, :492 -
   IT8368_FIXATTR_OFFSET). */
constexpr uint32_t kFixAttrShift  = 25;
constexpr uint32_t kFixAttrOffMask = 0x01FFFFFFu;

constexpr uint32_t kMemOffMask = 0x03FFFFFFu;

}  /* namespace */

bool Pr31x00CardSpace::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    if (!bd) return false;
    const std::string_view soc = bd->GetSocId();
    return soc == SocId::Pr31500 || soc == SocId::Pr31700;
}

void Pr31x00CardSpace::ProvideSockets(PcmciaSlot* socket0, PcmciaSlot* socket1) {
    sockets_[0] = socket0;
    sockets_[1] = socket1;
}

PcmciaSlot* Pr31x00CardSpace::Socket(int n) const {
    return (n == 0 || n == 1) ? sockets_[n] : nullptr;
}

void Pr31x00CardSpace::ProvideCardBuffer(Pr31x00CardBuffer* buffer) {
    buffer_ = buffer;
}

/* CARDnIOEN selects I/O over Attribute (TMPR3911.pdf PDF p.102, §4.2.1), and a
   fixed-attribute buffer overrides it: the buffer decodes attribute from address
   bit 25 while leaving CARDnIOEN set (it8368.c:562-567). */
PcmciaSlot* Pr31x00CardSpace::DecodeCtrl(uint32_t off, bool* io_space,
                                         uint32_t* card_offset) const {
    const int card = static_cast<int>((off >> kCardShift) & 1u);

    if (buffer_ && !buffer_->CardInterfaceEnabled()) {
        *io_space    = false;
        *card_offset = 0;
        return nullptr;
    }

    if (buffer_ && buffer_->FixedAttributeIo()) {
        *io_space    = ((off >> kFixAttrShift) & 1u) == 0u;
        *card_offset = off & kFixAttrOffMask;
        return sockets_[card];
    }

    *card_offset = off & kCtrlOffMask;
    const auto& biu = emu_.Get<Pr31x00Biu>();
    *io_space = card ? biu.Card2IoSpace() : biu.Card1IoSpace();
    return sockets_[card];
}

/* "Card 1 and Card 2 are mapped into kuseg space for memory accesses and
   kernel-only space for IO and Attribute accesses" (TMPR3911.pdf PDF p.102,
   §4.2.1), so this kuseg window is common memory over its whole 64 MB. */
PcmciaSlot* Pr31x00CardSpace::DecodeMem(uint32_t off, uint32_t* card_offset) const {
    const int card = static_cast<int>((off >> kCardShift) & 1u);
    *card_offset = off & kMemOffMask;
    return sockets_[card];
}

uint8_t Pr31x00CardSpace::ReadCtrl8(uint32_t off) {
    bool io; uint32_t o;
    PcmciaSlot* slot = DecodeCtrl(off, &io, &o);
    if (!slot) return kFloat8;
    return io ? slot->ReadIo8(o) : slot->ReadAttribute8(o);
}

uint16_t Pr31x00CardSpace::ReadCtrl16(uint32_t off) {
    bool io; uint32_t o;
    PcmciaSlot* slot = DecodeCtrl(off, &io, &o);
    if (!slot) return kFloat16;
    if (io) return slot->ReadIo16(o);
    /* Attribute memory drives even bytes only; the even byte images on both halves
       of the 16-bit bus. */
    const uint8_t v = slot->ReadAttribute8(o & ~1u);
    return static_cast<uint16_t>((v << 8) | v);
}

void Pr31x00CardSpace::WriteCtrl8(uint32_t off, uint8_t value) {
    bool io; uint32_t o;
    PcmciaSlot* slot = DecodeCtrl(off, &io, &o);
    if (!slot) return;
    if (io) slot->WriteIo8(o, value); else slot->WriteAttribute8(o, value);
}

void Pr31x00CardSpace::WriteCtrl16(uint32_t off, uint16_t value) {
    bool io; uint32_t o;
    PcmciaSlot* slot = DecodeCtrl(off, &io, &o);
    if (!slot) return;
    if (io) slot->WriteIo16(o, value);
    else    slot->WriteAttribute8(o & ~1u, static_cast<uint8_t>(value));
}

uint8_t Pr31x00CardSpace::ReadMem8(uint32_t off) {
    uint32_t o;
    PcmciaSlot* slot = DecodeMem(off, &o);
    if (!slot) return kFloat8;
    return slot->ReadCommon8(o);
}

uint16_t Pr31x00CardSpace::ReadMem16(uint32_t off) {
    uint32_t o;
    PcmciaSlot* slot = DecodeMem(off, &o);
    if (!slot) return kFloat16;
    return slot->ReadCommon16(o);
}

void Pr31x00CardSpace::WriteMem8(uint32_t off, uint8_t value) {
    uint32_t o;
    PcmciaSlot* slot = DecodeMem(off, &o);
    if (!slot) return;
    slot->WriteCommon8(o, value);
}

void Pr31x00CardSpace::WriteMem16(uint32_t off, uint16_t value) {
    uint32_t o;
    PcmciaSlot* slot = DecodeMem(off, &o);
    if (!slot) return;
    slot->WriteCommon16(o, value);
}

void Pr31x00CardSpace::SaveState(StateWriter& w) {
    for (int i = 0; i < 2; ++i) {
        PcmciaSlot* s = sockets_[i];
        w.Write<uint8_t>("socket_present", s ? 1u : 0u);
        if (s) s->SaveSlotState(w);
    }
}

void Pr31x00CardSpace::RestoreState(StateReader& r) {
    for (int i = 0; i < 2; ++i) {
        uint8_t present = 0; r.Read("socket_present", present);
        if ((present != 0u) != (sockets_[i] != nullptr))
            r.Reject("socket %d is %s in the image and %s in this build", i,
                     present ? "wired" : "absent", sockets_[i] ? "wired" : "absent");
        if (sockets_[i]) sockets_[i]->RestoreSlotState(r);
    }
}

void Pr31x00CardSpace::PostRestore() {
    for (PcmciaSlot* s : sockets_)
        if (s) s->PostRestoreSlot();
}

REGISTER_SERVICE(Pr31x00CardSpace);
