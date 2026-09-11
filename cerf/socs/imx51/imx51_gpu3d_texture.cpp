#include "imx51_gpu3d_texture.h"
#include "imx51_gpu3d_memory.h"
#include "imx51_gpu3d_tiling.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../boards/board_context.h"
#include <algorithm>
#include <cmath>
#include <bit>

REGISTER_SERVICE(Imx51Gpu3dTexture);
bool Imx51Gpu3dTexture::ShouldRegister() {
    auto* board = emu_.TryGet<BoardContext>();
    return board && board->GetSoc() == SocFamily::iMX51;
}

/* Mesa e97ad748, a2xx.xml: A2XX_SQ_TEX; instr-a2xx.h: instr_fetch_tex_t;
   fd2_gmem.c: emit_mem2gmem_surf. */
Imx51Gpu3dVec4 Imx51Gpu3dTexture::Sample(const std::unordered_map<uint32_t,uint32_t>& registers,
    uint32_t mmu_config, uint32_t slot, const Imx51Gpu3dVec4& coordinates,
    std::array<uint32_t,3> instruction, const Imx51Gpu3dVec4* dx, const Imx51Gpu3dVec4* dy, float register_lod) {

    auto fail = [&](const char* reason, uint32_t value) {
        emu_.Get<Fatal>().Die("GPU texture %s slot=%u value=%08X", reason, slot, value);
    };
    if (slot >= 32u) fail("slot", slot);
    const bool query_weights = (instruction[0] & 31u) == 19u;
    const bool query_border = (instruction[0] & 31u) == 16u;
    std::array<uint32_t,6> state{};
    for (uint32_t i = 0; i < state.size(); ++i) {
        const auto found = registers.find(0x4800u + slot * 6u + i);
        if (found == registers.end()) fail("missing descriptor", i);
        state[i] = found->second;
    }
    const uint32_t format = state[1] & 63u, pitch = ((state[0] >> 22) & 511u) * 32u;
    const uint32_t width = (state[2] & 8191u) + 1u, height = ((state[2] >> 13) & 8191u) + 1u;
    const uint32_t clamp_x = (state[0] >> 10) & 7u, clamp_y = (state[0] >> 13) & 7u;
    const bool tiled = (state[0] & 0x80000000u) != 0;
    const uint32_t dimension = (state[5] >> 9) & 3u;
    const bool cube = dimension == 3u;
    if ((state[0] & 0x000003FDu) != 0 || ((state[1] >> 6) & 15u) != 0 || (state[3] & 1u) != 0)
        fail("unsupported type/sign/endian", state[0]);
    if ((dimension != 1u && !cube) || (state[2] >> 26) != 0 || pitch < width)
        fail("unsupported dimension/pitch", state[5]);
    auto compute_lod = [&] {
        if (!dx || !dy) fail("unavailable texture gradients",instruction[0]);
        for (unsigned i = 0; i < 2u; ++i)
            if (!std::isfinite((*dx)[i]) || !std::isfinite((*dy)[i])) fail("nonfinite texture gradients",slot);
        const double sx = (instruction[0] & (1u << 25)) ? 1.0 : double(width);
        const double sy = (instruction[0] & (1u << 25)) ? 1.0 : double(height);
        /* Khronos GLES 2.0.25 section 3.7.7, equation 3.12. */
        const double rho = (std::max)(std::hypot((*dx)[0]*sx,(*dx)[1]*sy),
                                     std::hypot((*dy)[0]*sx,(*dy)[1]*sy));
        return rho > 0.0 ? std::log2(rho) : -INFINITY;
    };
    if ((instruction[0] & 31u) == 17u) {
        const uint32_t aniso = (instruction[1] >> 18) & 7u;
        if (cube || (instruction[2] & 0x7FFFFFFDu) || (instruction[1] & 0x60000000u) ||
            (aniso != 0u && aniso != 7u)) fail("unsupported LOD query controls",instruction[1]);
        // Provisional Xenos query model: implicit, unbiased/unclamped LOD in X.
        // Leave YZW zero; ordinary fetch swizzles can retain destination lanes.
        return {static_cast<float>(compute_lod()),0,0,0};
    }
    if ((clamp_x != 0u && clamp_x != 1u && clamp_x != 2u) ||
        (clamp_y != 0u && clamp_y != 1u && clamp_y != 2u)) fail("unsupported clamp", state[0]);
    if ((state[4] & 0x003FFC3Cu) != 0 || (state[3] & 0xFE07E000u) != 0 ||
        (instruction[2] & 0x7FFFFFFCu) != 0) fail("unsupported LOD/offset", state[4]);
    const uint32_t aniso = (instruction[1] >> 18) & 7u, arbitrary = (instruction[1] >> 21) & 7u;
    const uint32_t reg_lod = (instruction[1] >> 29) & 3u;
    const bool computed_lod = (instruction[1] & (1u << 28)) != 0 || (instruction[2] & 1u) != 0;
    if ((aniso != 0u && aniso != 7u) || (arbitrary != 0u && arbitrary != 7u) ||
        reg_lod > 1u) fail("unsupported anisotropy/register LOD",instruction[1]);
    if (reg_lod && std::isnan(register_lod)) fail("NaN register LOD",instruction[1]);
    auto filter = [&](uint32_t shift, uint32_t constant_shift) {
        const uint32_t selected = (instruction[1] >> shift) & 3u;
        return selected == 3u ? (state[3] >> constant_shift) & 3u : selected;
    };
    const uint32_t mag = filter(12u,19u), min = filter(14u,21u), mip = filter(16u,23u);
    const bool mipmapped = mip <= 1u;
    if (mag > 1u || mag != min || (mip != 2u && !mipmapped)) fail("unsupported filter",instruction[1]);
    if (format != 6u && format != 4u && format != 2u && format != 15u && format != 10u) fail("unsupported format", format);
    const uint32_t bytes = format == 6u ? 4u : (format == 4u || format == 15u || format == 10u) ? 2u : 1u;
    uint32_t face = 0;
    if (cube) {
        // Mesa fd2_layout_resource allocates each linear face with a 32-row
        // padded height and 4096-byte size alignment; fd2_tile_mode disables tiling.
        if (tiled || mipmapped || width != height || (state[5] & 0xFFFu) != 0x600u ||
            clamp_x != 2u || clamp_y != 2u || (instruction[0] & (1u << 25)))
            fail("unsupported cube layout/filter",state[5]);
        const float selected = coordinates[2];
        if (!std::isfinite(selected) || selected < 0 || selected > 5 || selected != std::floor(selected))
            fail("cube face",slot);
        face = static_cast<uint32_t>(selected);
    }
    double lod = 0;
    const uint32_t last_level = std::bit_width(width)-1u;
    if (mipmapped) {
        /* i.MX51 libGLESv2.so.2 rb_init_tile_info 0xE7AA8: uncompressed bytes-per-texel layout;
           NXP yamato_enum.h: FMT_8_8_8_8=6, FMT_8_8=10. */
        const char* invalid = !tiled ? "mip linear layout" : (format != 10u && format != 6u) ? "mip format" :

            (width < 32u || width != height || !std::has_single_bit(width)) ? "mip dimensions" : pitch != width ? "mip pitch" :
            state[4] != (last_level << 6) ? "mip levels/LOD state" : (state[5] & 0xFFFu) != 0xA00u ? "mip packing controls" :
            (instruction[0] & (1u << 25)) ? "mip denormalized coordinates" : nullptr;
        if (invalid) fail(invalid,state[5]);
        if (computed_lod) lod = compute_lod();
        // Mesa emits register mode 1 for its extra LOD/bias source, with
        // computed LOD enabled in fragment shaders and disabled in vertex shaders.
        // Model it as a bias to computed LOD, or an explicit LOD when disabled.
        if (reg_lod) lod += register_lod;
        if (std::isnan(lod)) fail("indeterminate combined LOD",instruction[1]);
        lod = std::clamp(lod, 0.0, double(last_level));
    }
    auto sample_level = [&](uint32_t level) {
    const uint32_t level_width = (std::max)(1u,width >> level), level_height = (std::max)(1u,height >> level);
    /* Same-chip libGLESv2.so.2 rb_init_tile_info 0xE7AA8: 32-texel pitch alignment, 4096-byte allocations, 16-texel tail. */
    const uint32_t tail_level = last_level >= 4u ? last_level-4u : 0u;
    const uint32_t level_pitch = level ? (std::max)(32u,pitch >> level) : pitch;
    uint32_t mip_x = 0, mip_y = 0;
    uint64_t base = (level ? state[5] : state[1]) & 0xFFFFF000u;
    if (cube) base += face * ((uint64_t(pitch) * ((height + 31u) & ~31u) * bytes + 4095u) & ~uint64_t{4095u});
    if (level) {
        for (uint32_t preceding = 1; preceding < (std::min)(level,tail_level); ++preceding) {
            const uint64_t side = (std::max)(32u,width >> preceding);
            base += (side*side*bytes+4095u) & ~uint64_t{4095u};
        }
        if (level >= tail_level) {
            const uint32_t relative = level-tail_level;
            if (relative < 3u) mip_x = 16u >> relative;
            else mip_y = 16u >> (relative-2u);
        }
    }
    if (base > UINT32_MAX) fail("mip address overflow",level);
    double u = coordinates[0], v = coordinates[1];
    if (!std::isfinite(u) || !std::isfinite(v)) fail("nonfinite coordinate", instruction[0]);
    // Mesa ir2_nir emits CUBE, reciprocal major axis, +1.5, then YXW fetch.
    if (cube) { u -= 1.0; v -= 1.0; }
    if ((instruction[0] & (1u << 25)) == 0) { u *= level_width; v *= level_height; }
    auto reduce = [](double x, uint32_t size, uint32_t clamp) {
        if (clamp == 2u) return std::clamp(x, 0.0, double(size));
        const double period = double(size) * (clamp == 1u ? 2.0 : 1.0);
        return x - std::floor(x / period) * period;
    };
    u = reduce(u,level_width,clamp_x); v = reduce(v,level_height,clamp_y);
    // Provisional Xenos query model: border contribution in X. The accepted
    // repeat/mirror/edge modes never sample border; border clamp modes still reject.
    if (query_border) return Imx51Gpu3dVec4{};
    if (query_weights) {
        // Provisional Xenos layout: XY spatial factors at the lower mip, Z=0
        // for 2D/cube, W mip factor. Point filtering has no interpolation.
        const float fx = mag ? static_cast<float>(u - 0.5 - std::floor(u - 0.5)) : 0.0f;
        const float fy = mag ? static_cast<float>(v - 0.5 - std::floor(v - 0.5)) : 0.0f;
        return Imx51Gpu3dVec4{fx,fy,0,static_cast<float>(lod - std::floor(lod))};
    }
    auto& memory = emu_.Get<Imx51Gpu3dMemory>();
    const auto* data = tiled ? nullptr : memory.ReadSpan(base,
        uint64_t(height - 1u) * pitch * bytes + uint64_t(width) * bytes, mmu_config);
    auto index = [](int value, uint32_t size, uint32_t clamp) {
        const int n = static_cast<int>(size);
        if (clamp == 2u) return std::clamp(value, 0, n - 1);
        const int period = clamp == 1u ? n * 2 : n;
        int wrapped = value % period; if (wrapped < 0) wrapped += period;
        return wrapped >= n ? period - wrapped - 1 : wrapped;
    };
    auto texel = [&](int x, int y) {
        x = index(x,level_width,clamp_x); y = index(y,level_height,clamp_y);
        const uint8_t* p = tiled ? memory.ReadSpan(Imx51Gpu3dTiledAddress(static_cast<uint32_t>(base),level_pitch,bytes,
            static_cast<uint32_t>(x)+mip_x,static_cast<uint32_t>(y)+mip_y),bytes,mmu_config) :
            data + (uint64_t(y) * pitch + static_cast<uint32_t>(x)) * bytes;
        Imx51Gpu3dVec4 raw{};
        if (bytes == 4u) for (unsigned c = 0; c < 4; ++c) raw[c] = float(p[c]) / 255.0f;
        else if (bytes == 2u) {
            const uint32_t packed = uint32_t(p[0]) | (uint32_t(p[1]) << 8);
            /* Mesa e97ad748, fd2_util.c: pipe2surface, CASE(8,8,0,0), FMT_8_8. */
            if (format == 10u) raw = {float(p[0])/255.0f,float(p[1])/255.0f,0.0f,1.0f};
            else if (format == 15u) for (unsigned i=0;i<4;++i) raw[i]=float((packed>>(i*4u))&15u)/15.0f;
            else raw = {float(packed & 31u) / 31.0f,float((packed >> 5) & 63u) / 63.0f,
                   float((packed >> 11) & 31u) / 31.0f,1.0f};
        } else raw = {float(p[0]) / 255.0f,0.0f,0.0f,1.0f};
        Imx51Gpu3dVec4 result{};
        for (unsigned c = 0; c < 4; ++c) {
            const uint32_t swizzle = (state[3] >> (1u + c * 3u)) & 7u;
            if (swizzle > 5u) fail("unsupported swizzle", swizzle);
            result[c] = swizzle < 4u ? raw[swizzle] : swizzle == 5u ? 1.0f : 0.0f;
        }
        return result;
    };
    if (mag == 0u) return texel(static_cast<int>(std::floor(u)),static_cast<int>(std::floor(v)));
    u -= 0.5; v -= 0.5;
    const int x = static_cast<int>(std::floor(u)), y = static_cast<int>(std::floor(v));
    const float fx = static_cast<float>(u - x), fy = static_cast<float>(v - y);
    const auto a = texel(x,y), b = texel(x+1,y), c = texel(x,y+1), d = texel(x+1,y+1);
    Imx51Gpu3dVec4 result{};
    for (unsigned k = 0; k < 4; ++k) result[k] = std::lerp(std::lerp(a[k],b[k],fx),std::lerp(c[k],d[k],fx),fy);
    return result;
    };
    // Mesa instr-a2xx.h TEX_FILTER_POINT; GLES 2.0 equation 3.17:
    // nearest-mipmap filters select the closest level, with ties going lower.
    if (mip == 0u) lod = (std::max)(0.0, std::ceil(lod + 0.5) - 1.0);
    const uint32_t lower = static_cast<uint32_t>(std::floor(lod));
    auto result = sample_level(lower);
    if (!query_weights && !query_border && lod > lower) {
        const auto upper = sample_level(lower+1u);
        for (unsigned c = 0; c < 4u; ++c) result[c] = std::lerp(result[c],upper[c],static_cast<float>(lod-lower));
    }
    return result;
}
