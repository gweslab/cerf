#include "imx51_gpu3d_draw.h"
#include "imx51_gpu3d_memory.h"
#include "imx51_gpu3d_regs.h"
#include "imx51_gpu3d_shader.h"
#include "imx51_gpu3d_raster.h"
#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../state/state_stream.h"
#include <algorithm>
#include <bit>
#include <cmath>
#include <vector>

REGISTER_SERVICE(Imx51Gpu3dDraw);

bool Imx51Gpu3dDraw::ShouldRegister() {
    auto* board = emu_.TryGet<BoardContext>();
    return board && board->GetSocId() == SocId::Imx51;
}

[[noreturn]] void Imx51Gpu3dDraw::Reject(const char* reason, uint64_t value) {
    emu_.Get<Fatal>().Die("GPU draw %s (value 0x%016llX)", reason,
                          static_cast<unsigned long long>(value));
}

uint32_t Imx51Gpu3dDraw::Operand(const Imx51Gpu3dPacket& packet, uint32_t index, uint32_t mmu) {
    uint64_t address = 0;
    if (!packet.OperandAddress(index, address)) Reject("packet operand", index);
    return emu_.Get<Imx51Gpu3dMemory>().ReadPa32(address, mmu);
}

/* NXP linux-imx a1638da9, gsl_drawctxt.c:84-103,511-516,1233-1240; yamato_registers.h: SQ_INST_STORE_MANAGMENT. */
uint32_t Imx51Gpu3dDraw::InstructionOffset(uint32_t stage, uint32_t start, uint32_t count) {
    if (stage > 1u) Reject("unsupported shared instruction load", stage);
    if (uint64_t(start) + count > instructions_[stage].size()) Reject("instruction extent", uint64_t(start) + count);
    return start;
}

std::span<const uint32_t> Imx51Gpu3dDraw::Program(uint32_t stage) {
    const uint32_t descriptor = start_size_[stage], count = descriptor & 0xFFFFu;
    const uint32_t offset = InstructionOffset(stage, descriptor >> 16, count);
    if (count == 0) return {};
    if (count % 3u != 0) Reject("incomplete shader", stage);
    for (uint32_t i = 0; i < count; ++i)
        if (!valid_[stage][offset + i]) Reject("uninitialized shader instruction", offset + i);
    return {instructions_[stage].data() + offset, count};
}

/* NXP linux-imx a1638da9, gsl_drawctxt.c:511-516,1200-1214. */
void Imx51Gpu3dDraw::Load(const Imx51Gpu3dPacket& packet, uint32_t mmu) {
    const bool immediate = packet.opcode == imx51_gpu3d_regs::kPm4OpImLoadImmediate;
    const uint32_t address_type = Operand(packet, 0, mmu), descriptor = Operand(packet, 1, mmu);
    const uint32_t stage = address_type & 3u, count = descriptor & 0xFFFFu;
    if ((immediate && (address_type > 2u || packet.payload_count != count + 2u)) ||
        (!immediate && packet.payload_count != 2u) || stage > 2u)
        Reject("shader load payload", packet.header);
    if (stage == 2u && count == 0u) { start_size_[stage] = descriptor; return; }
    const uint32_t offset = InstructionOffset(stage, descriptor >> 16, count);
    if (count + (start_size_[stage ^ 1u] & 0xFFFFu) > instructions_[stage].size())
        Reject("combined shader instruction capacity", count);
    auto& memory = emu_.Get<Imx51Gpu3dMemory>();
    if (count) memory.ReadSpan(immediate ? packet.address + 12u : address_type & ~3u,
                               uint64_t(count) * 4u, mmu);
    std::vector<uint32_t> words(count);
    for (uint32_t i = 0; i < count; ++i)
        words[i] = immediate ? Operand(packet, i + 2u, mmu) :
            memory.ReadPa32(uint64_t(address_type & ~3u) + uint64_t(i) * 4u, mmu);
    std::copy(words.begin(), words.end(), instructions_[stage].begin() + offset);
    std::fill_n(valid_[stage].begin() + offset, count, uint8_t{1});
    start_size_[stage] = descriptor;
}

/* NXP linux-imx a1638da9, gsl_drawctxt.c:1269-1283. */
void Imx51Gpu3dDraw::Store(const Imx51Gpu3dPacket& packet, uint32_t mmu) {
    if (packet.payload_count != 2u) Reject("shader store payload", packet.header);
    const uint32_t address_type = Operand(packet, 0, mmu), descriptor_address = Operand(packet, 1, mmu);
    const uint32_t stage = address_type & 3u;
    if (stage > 2u || (descriptor_address & 3u)) Reject("shader store stage/address", address_type);
    const uint32_t descriptor = start_size_[stage], count = descriptor & 0xFFFFu;
    const uint32_t offset = count ? InstructionOffset(stage, descriptor >> 16, count) : 0u;
    auto& memory = emu_.Get<Imx51Gpu3dMemory>();
    if (count) memory.WriteSpan(address_type & ~3u, uint64_t(count) * 4u, mmu);
    memory.WriteSpan(descriptor_address, 4u, mmu);
    for (uint32_t i = 0; i < count; ++i)
        if (!valid_[stage][offset + i]) Reject("store uninitialized shader", offset + i);
    for (uint32_t i = 0; i < count; ++i)
        memory.WritePa32(uint64_t(address_type & ~3u) + uint64_t(i) * 4u, instructions_[stage][offset + i], mmu);
    memory.WritePa32(descriptor_address, descriptor, mmu);
}

void Imx51Gpu3dDraw::Packet(const Imx51Gpu3dPacket& packet,
                           std::unordered_map<uint32_t, uint32_t>& registers, uint32_t mmu) {
    using namespace imx51_gpu3d_regs;
    switch (packet.opcode) {
        case kPm4OpImLoad: case kPm4OpImLoadImmediate: Load(packet, mmu); return;
        case kPm4OpImStore: Store(packet, mmu); return;
        /* NXP linux-imx a1638da9, gsl_drawctxt.c:1233-1240; yamato_registers.h: SQ_INST_STORE_MANAGMENT. */
        case kPm4OpSetShaderBases: {
            const uint32_t value = Operand(packet, 0, mmu);
            if (packet.payload_count != 1u || (value & 0xF000F000u) != 0x80000000u ||
                (value & 0xFFFu) >= 512u || ((value >> 16) & 0xFFFu) >= 512u)
                Reject("shader partition", value);
            bases_ = value;
            registers[kIdxSqInstStoreManagment] = value & 0x0FFF0FFFu;
            return;
        }
        /* NXP linux-imx a1638da9, gsl_pm4types.h: PM4_SET_BIN_BASE_OFFSET. */
        case 0x4Bu:
            if (packet.payload_count != 1u) Reject("bin base payload", packet.header);
            bin_base_ = Operand(packet, 0, mmu); return;
        case kPm4OpDrawIndx: case 0x34u: Draw(packet, registers, mmu); return;
        default: Reject("unsupported packet", packet.header);
    }
}

void Imx51Gpu3dDraw::SaveState(StateWriter& writer) {
    writer.Write("instructions", instructions_); writer.Write("valid", valid_); writer.Write("start_size", start_size_);
    writer.Write("bases", bases_); writer.Write("bin_base", bin_base_);
}
void Imx51Gpu3dDraw::RestoreState(StateReader& reader) {
    reader.Read("instructions", instructions_); reader.Read("valid", valid_); reader.Read("start_size", start_size_);
    reader.Read("bases", bases_); reader.Read("bin_base", bin_base_);
}

/* Mesa e97ad748, fd2_gmem.c:591-600,609-635; fd2_util.c: fd2_pipe2color;
   NXP linux-imx a1638da9, yamato_registers.h: VGT_CURRENT_BIN_ID_MIN/MAX. */
void Imx51Gpu3dDraw::Export(const Imx51Gpu3dShaderState& state, uint32_t mmu) {
    for (const auto& output : state.memory_exports) {
        const uint32_t x = std::bit_cast<uint32_t>(output.address[0]);
        const uint32_t z = std::bit_cast<uint32_t>(output.address[2]);
        const uint32_t w = std::bit_cast<uint32_t>(output.address[3]);
        const float index = output.address[1];
        if ((x & 0xC0000000u) != 0x40000000u || z != 0x4B00D000u ||
            (w & 0xFF800000u) != 0x4B000000u || !std::isfinite(index) ||
            index < 0 || index >= static_cast<float>(w & 0x7FFFFFu) || std::floor(index) != index)
            Reject("unsupported memory export descriptor/index", z);
        std::array<uint32_t, 3> component{};
        for (uint32_t i = 0; i < component.size(); ++i) {
            if (!std::isfinite(output.data[i])) Reject("nonfinite bin coordinate", i);
            component[i] = static_cast<uint32_t>(std::clamp(output.data[i], 0.0f, 1.0f) * 255.0f);
        }
        const uint64_t address = uint64_t(x & 0x3FFFFFFFu) * 4u + static_cast<uint32_t>(index);
        auto* destination = emu_.Get<Imx51Gpu3dMemory>().WriteSpan(address, 1u, mmu);
        *destination = static_cast<uint8_t>((component[0] >> 5) | ((component[1] >> 5) << 3) |
                                             ((component[2] >> 6) << 6));
    }
}

/* NXP linux-imx a1638da9, yamato_registers.h: VGT_DRAW_INITIATOR/VGT_DMA_SIZE;
   Mesa e97ad748, freedreno_draw.h: fd_draw/fd_draw_emit; fd2_draw.c: draw_impl. */
void Imx51Gpu3dDraw::Draw(const Imx51Gpu3dPacket& packet,
                         const std::unordered_map<uint32_t, uint32_t>& registers, uint32_t mmu) {
    const uint32_t control = Operand(packet, 1, mmu), primitive = control & 0x3Fu;
    const uint32_t source = (control >> 6) & 3u, count = control >> 16;
    const bool bin = packet.opcode == 0x34u;
    const uint32_t width = (control & 0x800u) ? 4u : 2u, dma_operand = bin ? 4u : 2u;
    const uint32_t query = Operand(packet, 0, mmu);
    /* NXP a1638da9 PA_SU_SC_MODE_CNTL: reject face producers before shader exports,
       zero-count/degenerate returns, or raster work. FACE_KILL alone is a binning pass. */
    const auto face = registers.find(0x2205u);
    if (face == registers.end() || (face->second & 0xB0000000u))
        Reject("unsupported face production/modifiers", face == registers.end() ? UINT32_MAX : face->second);
    if (query != 0u || (control & 0x3700u) != 0u ||
        (primitive != 4u && primitive != 6u && primitive != 8u) || (source != 0u && source != 2u) ||
        (primitive == 8u && (bin || count != 3u)) ||
        (!bin && (control & 0xC000u)) || (bin && (control & 0xC000u) != 0xC000u) ||
        packet.payload_count != dma_operand + (source == 0u ? 2u : 0u))
        Reject("unsupported draw flags/primitive/extent", control);
    auto& memory = emu_.Get<Imx51Gpu3dMemory>();
    const uint8_t* indices = nullptr;
    const uint8_t* bin_bytes = nullptr;
    if (source == 0u) {
        const uint32_t address = Operand(packet, dma_operand, mmu);
        const uint32_t size = Operand(packet, dma_operand + 1u, mmu);
        if ((address % width) || (size & 0xFF000000u) || uint64_t(count) * width > size)
            Reject("index buffer extent/swap", size);
        if (size) indices = memory.ReadSpan(address, size, mmu);
    }
    if (bin) {
        const uint32_t offset = Operand(packet, 2, mmu), size = Operand(packet, 3, mmu);
        /* NXP linux-imx a1638da9, yamato_registers.h:2274-2292, VGT_BIN_SIZE. */
        const uint32_t extent = size & 0x00FFFFFFu, reserved = size & 0x3F000000u;
        const bool fetch = (size & 0x40000000u) != 0;
        const char* invalid = reserved ? "bin buffer reserved bits" : extent < count ? "bin buffer extent" :
            fetch ? "unsupported bin faceness fetch" : nullptr;
        if (invalid) Reject(invalid, size);
        /* Model RESET within the excluded face subsystem: all face writers and
           FETCH/cull consumers are rejected, including the C2D path. No face cursor
           is observable in this subset. See docs/gpu_bin_draws.md. */
        if (extent) bin_bytes = memory.ReadSpan(uint64_t(bin_base_) + offset, extent, mmu);
    }
    std::vector<uint32_t> fetched(count);
    for (uint32_t i = 0; i < count; ++i) {
        fetched[i] = i;
        if (indices) {
            fetched[i] = 0;
            for (uint32_t byte = 0; byte < width; ++byte)
                fetched[i] |= uint32_t(indices[uint64_t(i) * width + byte]) << (byte * 8u);
        }
    }
    /* NXP linux-imx a1638da9, gsl_yamato.c:275-300; Mesa e97ad748, fd2_draw.c:75-105. */
    if (bin && primitive == 4u && count == 3u && fetched[0] == fetched[1] && fetched[1] == fetched[2]) return;
    std::vector<uint8_t> visible(count, !bin), needed(count, !bin);
    if (bin) {
        /* Mesa e97ad748 fd2_gmem.c:609-630; physical SYNC 2 B023_00 cases 6/9/10.
           XY bins use the same vertex triplets as list/strip assembly below. */
        const auto low = registers.find(0x2207u), high = registers.find(0x2203u);
        if (primitive == 4u && count % 3u) Reject("unsupported bin primitive/count", control);
        if (low == registers.end() || high == registers.end()) Reject("missing bin bounds", packet.address);
        if ((low->second | high->second) & ~0x3Fu) Reject("unsupported bin guard band", low->second);
        for (unsigned shift : {0u, 3u})
            if (((low->second >> shift) & 7u) > ((high->second >> shift) & 7u))
                Reject("reversed bin bounds", low->second);
        for (uint32_t i = 0; i < count; ++i)
            if ((bin_bytes[i] >> 6) != 1u) Reject("unsupported bin Z code", bin_bytes[i]);
        for (uint32_t i = 2; i < count; i += primitive == 4u ? 3u : 1u) {
            bool overlap = true;
            for (unsigned shift : {0u, 3u}) {
                const unsigned a = (bin_bytes[i-2] >> shift) & 7u;
                const unsigned b = (bin_bytes[i-1] >> shift) & 7u;
                const unsigned c = (bin_bytes[i] >> shift) & 7u;
                overlap &= std::max({a,b,c}) >= ((low->second >> shift) & 7u) &&
                           std::min({a,b,c}) <= ((high->second >> shift) & 7u);
            }
            visible[i] = overlap;
            if (overlap) needed[i-2] = needed[i-1] = needed[i] = 1;
        }
        if (std::none_of(visible.begin(), visible.end(), [](uint8_t v) { return v != 0; })) return;
    }
    /* NXP linux-imx a1638da9, yamato_registers.h: VGT_INDX_OFFSET; Mesa e97ad748, fd2_draw.c:75-76. */
    const auto offset_reg = registers.find(0x2102u);
    if (offset_reg == registers.end() || (offset_reg->second & 0xFF000000u))
        Reject("unsupported index offset", offset_reg == registers.end() ? UINT32_MAX : offset_reg->second);
    const auto vertex_program = Program(0), pixel_program = Program(1);
    if (count && vertex_program.empty()) Reject("vertex shader not loaded", packet.address);
    std::vector<Imx51Gpu3dShaderState> vertices(count);
    for (uint32_t i = 0; i < count; ++i) {
        if (!needed[i]) continue;
        const uint64_t effective = uint64_t(fetched[i]) + offset_reg->second;
        if (effective > 0xFFFFFFu) Reject("unsupported vertex index arithmetic", effective);
        const uint32_t index = static_cast<uint32_t>(effective);
        if (index > 0xFFFFFFu) Reject("unsupported vertex index width", index);
        vertices[i].registers[0][0] = static_cast<float>(index);
        /* Mesa e97ad748, fd2_program.c: GEN_INDEX_VTX; ir2_nir.c: binning index input 2. */
        const auto program_control = registers.find(0x2180u);
        if (program_control != registers.end() && (program_control->second & 0x80000000u))
            vertices[i].registers[2][0] = static_cast<float>(i);
        emu_.Get<Imx51Gpu3dShader>().Run(vertex_program, false, registers, mmu, vertices[i]);
        if (bin && !vertices[i].memory_exports.empty()) Reject("unsupported bin replay memory exports", packet.address);
        Export(vertices[i], mmu);
        if (!(vertices[i].export_mask & (uint64_t{1} << 62))) Reject("vertex position not exported", i);
    }
    /* NXP linux-imx a1638da9, gsl_drawctxt.c:389-394,806-810,1107-1121. */
    if (primitive == 8u) {
        const auto& a = vertices[0].exports[62];
        const auto& b = vertices[1].exports[62];
        const auto& c = vertices[2].exports[62];
        if (a[1] != b[1] || a[0] != c[0] || a[3] != b[3] || a[3] != c[3])
            Reject("unsupported rectangle alignment/perspective", packet.address);
        Imx51Gpu3dShaderState fourth;
        fourth.export_mask = vertices[0].export_mask & vertices[1].export_mask & vertices[2].export_mask;
        for (uint32_t slot = 0; slot < fourth.exports.size(); ++slot)
            if (fourth.export_mask & (uint64_t{1} << slot))
                for (uint32_t component = 0; component < 4; ++component)
                    fourth.exports[slot][component] = vertices[1].exports[slot][component] +
                        vertices[2].exports[slot][component] - vertices[0].exports[slot][component];
        emu_.Get<Imx51Gpu3dRaster>().Triangle({vertices[0],vertices[1],vertices[2]}, registers, pixel_program, mmu);
        emu_.Get<Imx51Gpu3dRaster>().Triangle({vertices[2],vertices[1],fourth}, registers, pixel_program, mmu);
        return;
    }
    for (uint32_t i = 2; i < count; i += primitive == 4u ? 3u : 1u) {
        if (!visible[i]) continue;
        const uint32_t a = primitive == 6u && (i & 1u) ? i - 1u : i - 2u;
        const uint32_t b = primitive == 6u && (i & 1u) ? i - 2u : i - 1u;
        const std::array<Imx51Gpu3dShaderState, 3> triangle{vertices[a], vertices[b], vertices[i]};
        emu_.Get<Imx51Gpu3dRaster>().Triangle(triangle, registers, pixel_program, mmu);
    }
}
