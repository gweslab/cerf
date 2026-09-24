#include "imx51_gpu3d_context.h"
#include "imx51_gpu3d_memory.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../state/state_stream.h"
#include <vector>

REGISTER_SERVICE(Imx51Gpu3dContext);

bool Imx51Gpu3dContext::ShouldRegister() {
    auto* board = emu_.TryGet<BoardContext>();
    return board && board->GetSocId() == SocId::Imx51;
}

/* NXP linux-imx a1638da9, gsl_drawctxt.c:74-107,1005-1076; gsl_ringbuffer.h:64. */
void Imx51Gpu3dContext::Load(const Imx51Gpu3dPacket& packet,
                            std::unordered_map<uint32_t, uint32_t>& registers, uint32_t config) {
    auto& memory = emu_.Get<Imx51Gpu3dMemory>();
    auto& fatal = emu_.Get<Fatal>();
    if (packet.payload_count < 3u || (packet.payload_count & 1u) == 0u)
        fatal.Die("GPU context invalid packet length %u", packet.payload_count);
    memory.ReadSpan(packet.address, uint64_t(packet.payload_count + 1u) * 4u, config);
    const uint32_t address = memory.ReadPa32(packet.address + 4u, config);
    const uint32_t first = memory.ReadPa32(packet.address + 8u, config);
    const uint32_t type = (first >> 16) & 7u;
    if ((address & 0x1FFFu) > 1u || (first & ~0x0107FFFFu) != 0u || (type != 0u && type != 1u && type != 4u))
        fatal.Die("GPU context unsupported address/type %08X %08X", address, first);
    const uint32_t slot = type == 4u ? 2u : type;
    const uint32_t base = type == 4u ? 0x2000u : type == 1u ? 0x4800u : 0x4000u;
    const uint32_t limit = type == 4u ? 1024u : type == 1u ? 192u : 2048u;
    const uint32_t physical = address & ~0x1FFFu;
    const bool enabled = (first & 0x01000000u) != 0u;
    /* NXP linux-imx a1638da9, gsl_drawctxt.c:1023-1044: force mismatch and shadow enable. */
    const bool load = (address & 1u) || !banks_[slot].enabled || banks_[slot].address != physical;
    std::vector<std::pair<uint32_t, uint32_t>> values;
    for (uint32_t operand = 1u; operand < packet.payload_count; operand += 2u) {
        const uint32_t descriptor = memory.ReadPa32(packet.address + uint64_t(operand + 1u) * 4u, config);
        const uint32_t count = memory.ReadPa32(packet.address + uint64_t(operand + 2u) * 4u, config);
        const uint32_t offset = descriptor & 0xFFFFu;
        const uint32_t allowed = operand == 1u ? 0x0107FFFFu : 0x0007FFFFu;
        if ((descriptor & ~allowed) || ((descriptor >> 16) & 7u) != type || offset > limit || count > limit - offset)
            fatal.Die("GPU context invalid range %08X %u", descriptor, count);
        if (count && load) {
            memory.ReadSpan(uint64_t(physical) + uint64_t(offset) * 4u, uint64_t(count) * 4u, config);
            for (uint32_t word = 0; word < count; ++word)
                values.emplace_back(base + offset + word,
                    memory.ReadPa32(uint64_t(physical) + uint64_t(offset + word) * 4u, config));
        }
    }
    for (const auto& [index, value] : values) registers[index] = value;
    banks_[slot] = {physical, enabled};
}

/* NXP linux-imx a1638da9, gsl_drawctxt.c:620-636,1043,1063,1074: whole-bank shadowing. */
void Imx51Gpu3dContext::ShadowWrite(uint32_t index, uint32_t value, uint32_t config) {
    uint32_t slot, base;
    if (index >= 0x4000u && index < 0x4800u) { slot = 0u; base = 0x4000u; }
    else if (index >= 0x4800u && index < 0x48C0u) { slot = 1u; base = 0x4800u; }
    else if (index >= 0x2000u && index < 0x2400u) { slot = 2u; base = 0x2000u; }
    else return;
    if (banks_[slot].enabled)
        emu_.Get<Imx51Gpu3dMemory>().WritePa32(uint64_t(banks_[slot].address) + uint64_t(index - base) * 4u, value, config);
}

void Imx51Gpu3dContext::SaveState(StateWriter& writer) {
    static_assert(StateVisitCoversAllBytes<Bank>(
                      [](Bank& b, StateFieldBytes& f) { Bank::Visit(b, f); }),
                  "Bank::Visit must name or skip every field of Bank");
    StateWriteField field(writer);
    for (Bank& bank : banks_) Bank::Visit(bank, field);
}
void Imx51Gpu3dContext::RestoreState(StateReader& reader) {
    StateReadField field(reader);
    for (Bank& bank : banks_) Bank::Visit(bank, field);
}
