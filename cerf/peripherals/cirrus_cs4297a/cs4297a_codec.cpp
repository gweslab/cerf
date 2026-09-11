#include "cs4297a_codec.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"

bool Cs4297aCodec::ShouldRegister() {
    auto* board = emu_.TryGet<BoardContext>();
    return board && board->GetBoard() == Board::SiemensMP377;
}

void Cs4297aCodec::OnReady() {
    Reset();
}

void Cs4297aCodec::Reset() {
    for (uint16_t& value : registers_) value = 0u;

    /* Cirrus CS4297A DS318PP6 register table and reset values; printed page
       29 defines Misc. Crystal Control index 60h, default 0023h and LOSM D0. */
    registers_[0x00u / 2u] = 0x1990u;
    registers_[0x02u / 2u] = 0x8000u;
    registers_[0x04u / 2u] = 0x8000u;
    registers_[0x06u / 2u] = 0x8000u;
    registers_[0x0Au / 2u] = 0x0000u;
    registers_[0x0Cu / 2u] = 0x8008u;
    registers_[0x0Eu / 2u] = 0x8008u;
    registers_[0x10u / 2u] = 0x8808u;
    registers_[0x12u / 2u] = 0x8808u;
    registers_[0x14u / 2u] = 0x8808u;
    registers_[0x16u / 2u] = 0x8808u;
    registers_[0x18u / 2u] = 0x8808u;
    registers_[0x1Au / 2u] = 0x0000u;
    registers_[0x1Cu / 2u] = 0x8000u;
    registers_[0x20u / 2u] = 0x0000u;
    registers_[0x22u / 2u] = 0x0000u;
    registers_[0x26u / 2u] = 0x0000u;
    registers_[0x28u / 2u] = 0x0200u;
    registers_[0x2Cu / 2u] = 0xBB80u;
    registers_[0x32u / 2u] = 0xBB80u;
    registers_[0x5Eu / 2u] = 0x0080u;
    registers_[0x60u / 2u] = 0x0023u;
    registers_[0x68u / 2u] = 0x0000u;
    registers_[0x7Cu / 2u] = 0x4352u;
    /* siemens_mp377_v1040 VGXaudio.dll sub_29884BC accepts the CRY
       identity 43525913h; the low byte identifies CS4297A revision C. */
    registers_[0x7Eu / 2u] = 0x5913u;
}

void Cs4297aCodec::WarmReset() {
    registers_[0x26u / 2u] &= static_cast<uint16_t>(~(1u << 12));
}

uint16_t Cs4297aCodec::PowerStatusValue(bool link_ready) const {
    const uint16_t control = static_cast<uint16_t>(registers_[0x26u / 2u] & 0xFF00u);
    const bool pr0_adc = (control & (1u << 8)) != 0u;
    const bool pr1_dac = (control & (1u << 9)) != 0u;
    const bool pr2_anl = (control & (1u << 10)) != 0u;
    const bool pr3_ref = (control & (1u << 11)) != 0u;
    const bool pr4_link = (control & (1u << 12)) != 0u;
    const bool pr5_clocks = (control & (1u << 13)) != 0u;

    uint16_t status = 0u;
    if (link_ready && !pr3_ref && !pr4_link && !pr5_clocks) status |= 0x0008u;
    if ((status & 0x0008u) != 0u && !pr2_anl) status |= 0x0004u;
    if ((status & 0x0004u) != 0u && !pr1_dac) status |= 0x0002u;
    if ((status & 0x0004u) != 0u && !pr0_adc) status |= 0x0001u;
    return static_cast<uint16_t>(control | status);
}

bool Cs4297aCodec::DacReady(bool link_ready) const {
    return (PowerStatusValue(link_ready) & 0x0002u) != 0u;
}

bool Cs4297aCodec::AdcReady(bool link_ready) const {
    return (PowerStatusValue(link_ready) & 0x0001u) != 0u;
}

bool Cs4297aCodec::LinkPowered() const {
    return (registers_[0x26u / 2u] & ((1u << 12) | (1u << 13))) == 0u;
}

uint16_t Cs4297aCodec::ReadRegister(uint32_t reg, bool link_ready) const {
    reg &= 0x7Eu;
    const uint32_t idx = reg / 2u;
    if (reg == 0x00u) return 0x1990u;
    if (reg == 0x26u) return PowerStatusValue(link_ready);
    if (reg == 0x28u) return static_cast<uint16_t>((registers_[0x5Eu / 2u] & 0x0080u) << 2u);
    /* Cirrus CS4297A Datasheet DS318PP6; siemens_mp377_v1040
       VGXaudio.dll sub_29884BC. */
    if (reg == 0x2Au) return 0u;
    if (reg == 0x2Cu || reg == 0x32u) return 0xBB80u;
    if (reg == 0x7Cu) return 0x4352u;
    if (reg == 0x7Eu) return 0x5913u;
    switch (reg) {
    case 0x02u: case 0x04u: case 0x06u: case 0x0Au: case 0x0Cu: case 0x0Eu:
    case 0x10u: case 0x12u: case 0x14u: case 0x16u: case 0x18u: case 0x1Au:
    case 0x1Cu: case 0x20u: case 0x22u: case 0x5Eu: case 0x60u: case 0x68u:
        return registers_[idx];
    default: emu_.Get<Fatal>().Die("[CS4297A] read of unmodelled codec register 0x%02X", reg);
    }
}

void Cs4297aCodec::WriteRegister(uint32_t reg, uint16_t value) {
    reg &= 0x7Eu;
    if (reg == 0x00u) {
        Reset();
        return;
    }
    switch (reg) {
    case 0x02u: case 0x04u: value &= 0xBF3Fu; break;
    case 0x06u: value &= 0x803Fu; break;
    case 0x0Au: value &= 0x801Eu; break;
    case 0x0Cu: value &= 0x801Fu; break;
    case 0x0Eu: value &= 0x805Fu; break;
    case 0x10u: case 0x12u: case 0x14u: case 0x16u: case 0x18u: value &= 0x9F1Fu; break;
    case 0x1Au: value &= 0x0707u; break;
    case 0x1Cu: value &= 0x8F0Fu; break;
    case 0x20u: value &= 0x2380u; break;
    case 0x22u: value &= 0x000Fu; break;
    case 0x26u: value &= 0xFF00u; break;
    case 0x5Eu: value &= 0x01B0u; break;
    /* DS318PP6 printed page 29: D0 is LOSM; reserved D5/D1 retain reset 1. */
    case 0x60u: value = static_cast<uint16_t>(0x0022u | (value & 0x0001u)); break;
    case 0x68u: value &= 0xCFFFu; break;
    case 0x28u: case 0x2Cu: case 0x32u: case 0x7Cu: case 0x7Eu: return;
    /* siemens_mp377_v1040 VGXaudio.dll 0x029884BC writes 1 to index 2Ah. */
    case 0x2Au: return;
    default: emu_.Get<Fatal>().Die("[CS4297A] write of unmodelled codec register 0x%02X = 0x%04X", reg, value);
    }
    registers_[reg / 2u] = value;
}

void Cs4297aCodec::SaveState(StateWriter& writer) const {
    writer.WriteBytes(registers_, sizeof(registers_));
}

void Cs4297aCodec::RestoreState(StateReader& reader) {
    reader.ReadBytes(registers_, sizeof(registers_));
}

REGISTER_SERVICE(Cs4297aCodec);
