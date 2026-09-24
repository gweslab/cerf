#include "sa11xx_mcp.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "sa11xx_mcp_codec.h"

/* MCDR2 (+0x10) command: reg=bits 20:17, bit16=R/W, data=15:0; MCSR (+0x18)
   bit12 CWC / bit13 CRC = write/read done (RE'd from 820 hplib.dll
   UcbRegister{Read,Write} @ 0x11A14FC / 0x11A156C). Routes to a registered
   Sa11xxMcpCodec; codec-less boards must read 0, not fault. */

bool Sa11xxMcp::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
}

void Sa11xxMcp::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint32_t Sa11xxMcp::ReadWord(uint32_t addr) {
    switch (addr - MmioBase()) {
        case 0x00: return mccr0_;
        case 0x08: return 0;   /* MCDR0 - audio data path is DMA-intercepted. */
        case 0x0C: return 0;   /* MCDR1. */
        case 0x10: return mcdr2_read_;   /* MCDR2: last codec read data. */
        case 0x18: return mcsr_;         /* MCSR: CWC|CRC sticky after access. */
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Sa11xxMcp::WriteWord(uint32_t addr, uint32_t value) {
    switch (addr - MmioBase()) {
        case 0x00: mccr0_ = value; return;
        case 0x08: case 0x0C: return;  /* MCDR0/1 - dropped. */
        case 0x10: RouteCodecCommand(value); return;
        case 0x18: return;             /* MCSR W1C status. */
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

uint32_t Sa11xxMcp::GetAudioSampleRateHz() const {
    const uint32_t asd = mccr0_ & 0x7Fu;
    if (asd < 6u) return 11025u;   /* MCCR0 not yet programmed; wavedev default. */
    return 11981000u / (32u * asd);
}

void Sa11xxMcp::RouteCodecCommand(uint32_t cmd) {
    const uint8_t reg      = static_cast<uint8_t>((cmd >> 17) & 0xFu);
    const bool    is_write = (cmd & 0x10000u) != 0;
    auto* codec = emu_.TryGet<Sa11xxMcpCodec>();
    if (is_write) {
        if (codec) codec->WriteReg(reg, static_cast<uint16_t>(cmd & 0xFFFFu));
    } else {
        mcdr2_read_ = codec ? codec->ReadReg(reg) : 0u;
    }
    mcsr_ |= 0x3000u;   /* synchronous codec: CWC (b12) + CRC (b13) done. */
}

void Sa11xxMcp::SaveState(StateWriter& w) {
    w.Write("mccr0", mccr0_);
    w.Write("mcsr", mcsr_);
    w.Write("mcdr2_read", mcdr2_read_);
    if (auto* codec = emu_.TryGet<Sa11xxMcpCodec>()) codec->SaveState(w);
}

void Sa11xxMcp::RestoreState(StateReader& r) {
    r.Read("mccr0", mccr0_);
    r.Read("mcsr", mcsr_);
    r.Read("mcdr2_read", mcdr2_read_);
    if (auto* codec = emu_.TryGet<Sa11xxMcpCodec>()) codec->RestoreState(r);
}

void Sa11xxMcp::PostRestore() {
    if (auto* codec = emu_.TryGet<Sa11xxMcpCodec>()) codec->PostRestore();
}

REGISTER_SERVICE(Sa11xxMcp);
