#include "imx51_gpu3d_raster.h"
#include "imx51_gpu3d_memory.h"
#include "imx51_gpu3d_tiling.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../state/state_stream.h"
#include "../../boards/board_context.h"
#include <algorithm>
#include <bit>
#include <cmath>
#include <vector>

/* ImageMagick config/thresholds.xml: o4x4 ordered thresholds, divisor 17. */
static uint32_t ApproximateDitherQuantize(float channel, uint32_t maximum, unsigned component,
    uint32_t x, uint32_t y, bool enabled) {
    const float scaled = channel * maximum;
    if (!enabled || component == 3u) return static_cast<uint32_t>(std::lround(scaled));
    constexpr uint8_t thresholds[4][4] = {{1,9,3,11},{13,5,15,7},{4,12,2,10},{16,8,14,6}};
    const double threshold = thresholds[y & 3u][x & 3u] / 17.0;
    return static_cast<uint32_t>(std::clamp(std::floor(scaled + 1.0 - threshold),0.0,double(maximum)));
}

REGISTER_SERVICE(Imx51Gpu3dRaster);
bool Imx51Gpu3dRaster::ShouldRegister() {
    auto* board = emu_.TryGet<BoardContext>();
    return board && board->GetSoc() == SocFamily::iMX51;
}
void Imx51Gpu3dRaster::SaveState(StateWriter& writer) {
    writer.Write(gmem_binding_); writer.Write(gmem_pitch_);
    writer.WriteBytes(gmem_.data(),gmem_.size());
}
void Imx51Gpu3dRaster::RestoreState(StateReader& reader) {
    reader.Read(gmem_binding_); reader.Read(gmem_pitch_);
    reader.ReadBytes(gmem_.data(),gmem_.size());
    if (gmem_binding_ != 0xFFFFFFFFu &&
        ((gmem_binding_ & 0xFF0u) != 0u || (gmem_binding_ & 0xFFFFF000u) >= gmem_.size() || gmem_pitch_ == 0 || gmem_pitch_ > 16383u ||
         ((gmem_binding_ & 15u) != 0u && (gmem_binding_ & 15u) != 2u && (gmem_binding_ & 15u) != 5u)))
        emu_.Get<Fatal>().Die("GPU raster invalid saved GMEM binding");
}

/* Khronos OpenGL ES 2.0.25 sections 2.13 and 2.13.1. */
void Imx51Gpu3dRaster::Triangle(const std::array<Imx51Gpu3dShaderState,3>& vertices,
    const std::unordered_map<uint32_t,uint32_t>& registers,
    std::span<const uint32_t> pixel_program, uint32_t mmu_config) {
    RasterWrites writes{{},gmem_binding_,gmem_pitch_};
    const auto clip = registers.find(0x2204), vte = registers.find(0x2206), raster = registers.find(0x2205);
    auto fail = [&](const char* reason, uint32_t value) {
        emu_.Get<Fatal>().Die("GPU raster unsupported %s value=%08X",reason,value);
    };
    if (clip != registers.end() && clip->second != 0u && clip->second != 0x10000u) fail("clip controls",clip->second);
    bool outside = false;
    const bool enabled = clip != registers.end() && clip->second == 0u && vte != registers.end() &&
        (vte->second == 0x43Fu || vte->second == 0x40Fu || vte->second == 0x30Fu) &&
        raster != registers.end() && (raster->second & 0xC0000000u) != 0x40000000u;
    if (enabled) for (unsigned i = 0; i < 3u; ++i) {
        const auto& p = vertices[i].exports[62];
        if (!(vertices[i].export_mask & (uint64_t{1} << 62))) fail("missing position",i);
        for (float component : p) if (!std::isfinite(component)) fail("homogeneous clipping",i);
        if (p[3] <= 0.0f) fail("homogeneous clipping",i);
        if (vte->second == 0x30Fu && p[3] != 1.0f) fail("premultiplied nonunit W",i);
        outside |= std::abs(p[0]) > p[3] || std::abs(p[1]) > p[3] || std::abs(p[2]) > p[3];
    }
    if (!outside) RasterizeTriangle(vertices,vertices,registers,pixel_program,mmu_config,writes);
    else {
        if (raster->second & 0xC000B818u) fail("MSAA/polygon/faceness",raster->second);
        std::vector<Imx51Gpu3dShaderState> polygon(vertices.begin(),vertices.end()), next;
        for (unsigned plane = 0; plane < 6u && !polygon.empty(); ++plane) {
            next.clear();
            const unsigned axis = plane / 2u;
            const double sign = (plane & 1u) ? -1.0 : 1.0;
            auto distance = [&](const Imx51Gpu3dShaderState& v) { return double(v.exports[62][3]) + sign * v.exports[62][axis]; };
            for (size_t i = 0; i < polygon.size(); ++i) {
                const auto& a = polygon[i]; const auto& b = polygon[(i+1u)%polygon.size()];
                const double da = distance(a), db = distance(b);
                if (da >= 0.0) next.push_back(a);
                if ((da < 0.0) == (db < 0.0)) continue;
                const auto& inside = da >= 0.0 ? a : b; const auto& out = da < 0.0 ? a : b;
                const double di = da >= 0.0 ? da : db, dout = da < 0.0 ? da : db;
                const double t = di / (di-dout);
                Imx51Gpu3dShaderState intersection{};
                intersection.export_mask = inside.export_mask & out.export_mask;
                /* Khronos EXT_gpu_shader4 issue 10: window-linear varying clipping. */
                const double varying_t = (raster->second & 0x100000u) ? t*out.exports[62][3] /
                    ((1.0-t)*inside.exports[62][3]+t*out.exports[62][3]) : t;
                for (unsigned slot = 0; slot < 64u; ++slot) if (intersection.export_mask & (uint64_t{1} << slot)) {
                    const double fraction = slot == 62u ? t : varying_t;
                    for (unsigned c = 0; c < 4u; ++c)
                        intersection.exports[slot][c] = static_cast<float>((1.0-fraction)*inside.exports[slot][c]+fraction*out.exports[slot][c]);
                }
                intersection.exports[62][axis] = static_cast<float>(-sign * intersection.exports[62][3]);
                next.push_back(std::move(intersection));
            }
            polygon.swap(next);
        }
        for (size_t i = 1; i+1 < polygon.size(); ++i)
            RasterizeTriangle({polygon[0],polygon[i],polygon[i+1]},vertices,registers,pixel_program,mmu_config,writes);
    }
    for (const auto& pixel : writes.pixels) for (unsigned i = 0; i < pixel.bytes; ++i) pixel.target[i] = pixel.data[i];
    gmem_binding_ = writes.binding; gmem_pitch_ = writes.pitch;
}

/* Mesa e97ad748 a2xx.xml: PA_CL_VTE_CNTL, PA_SU_VTX_CNTL, RB_COLOR_INFO;
   fd2_gmem.c: fmt2swap, fd2_emit_sysmem_prep, fd2_emit_tile_renderprep. */
void Imx51Gpu3dRaster::RasterizeTriangle(const std::array<Imx51Gpu3dShaderState,3>& vertices,
    const std::array<Imx51Gpu3dShaderState,3>& depth_vertices,
    const std::unordered_map<uint32_t,uint32_t>& registers,
    std::span<const uint32_t> pixel_program, uint32_t mmu_config, RasterWrites& writes) {
    auto fail = [&](const char* reason, uint32_t value) {
        emu_.Get<Fatal>().Die("GPU raster unsupported %s value=%08X",reason,value);
    };
    for (const auto& vertex : vertices)
        if ((vertex.export_mask & (uint64_t{1} << 62)) == 0) fail("missing position",0);
    const auto& p0 = vertices[0].exports[62];
    const auto& p1 = vertices[1].exports[62];
    const auto& p2 = vertices[2].exports[62];
    if (p0 == p1 || p1 == p2 || p2 == p0) return;
    auto reg = [&](uint32_t index) {
        const auto i = registers.find(index);
        if (i == registers.end()) fail("missing register",index);
        return i->second;
    };
    const uint32_t raster = reg(0x2205);
    /* Mesa e97ad748 fd2_emit.c:169-215, fd2_emit_state_binning;
       NXP a1638da9 yamato_registers.h:400, FACE_KILL_ENABLE. */
    if ((raster & 0xC0000000u) == 0x40000000u) return;
    const uint32_t vte = reg(0x2206), control = reg(0x2202);
    const uint32_t clip = reg(0x2204);
    if (clip != 0u && clip != 0x10000u) fail("clip controls",clip);
    /* Mesa e97ad748 a2xx.xml:1491-1502, PA_CL_VTE_CNTL. */
    if (vte != 0x43Fu && vte != 0x40Fu && vte != 0xB00u && vte != 0x30Fu) fail("viewport format",vte);
    if ((raster & 0xC000B818u) != 0) fail("MSAA/polygon/faceness",raster);
    /* NXP a1638da9 yamato_registers.h: RB_DEPTHCONTROL; yamato_enum.h: CompareFrag. */
    const uint32_t depth_control = reg(0x2200);
    /* Mesa e97ad748 fd2_zsa.c:38-70; NXP a1638da9 yamato_registers.h: RB_DEPTHCONTROL.STENCIL_ENABLE. */
    if (depth_control & 1u) fail("depth/stencil",depth_control);
    const bool depth_enabled = (depth_control & 2u) != 0;
    const bool depth_write = depth_enabled && (depth_control & 4u) != 0;
    /* NXP a1638da9 yamato_enum.h:1603-1617; Mesa e97ad748 a2xx.xml:1440-1449. */
    const uint32_t dither_mode = (control >> 12) & 3u;
    const bool blend = (control & 0x20u) == 0;
    const auto blend_register = registers.find(0x2201u);
    /* NXP a1638da9 BlendOpX/CombFuncX; Navigation 20260906_222205 RB_BLEND_CONTROL=07060706. */
    const bool measured_blend = blend && (control & ~0x3007u) == 0xC00u &&
        blend_register != registers.end() && blend_register->second == 0x07060706u;
    if (!measured_blend && (control & ~0x3007u) != 0x20u && (control & ~0x3007u) != 0xC20u)
        fail("blend/alpha/ROP/dither type",control);
    if (dither_mode == 3u) fail("dither mode",control);
    const uint32_t mode = reg(0x2208);
    if (mode != 4u && mode != 6u) fail("render mode",mode);
    const bool resolve = mode == 6u;
    if (resolve && depth_enabled) fail("resolve depth",depth_control);
    /* NXP a1638da9 gsl_drawctxt.c:960-989, build_sys2gmem_cmds: VTE=B00, mode=4. */
    if (vte == 0xB00u && !resolve && clip != 0x10000u) fail("window-space clipping",clip);
    const uint32_t info = reg(0x2001), surface = reg(0x2000), format = info & 15u;
    if ((surface & ~0x3FFFu) != 0 || (surface & 0x3FFFu) == 0) fail("surface/MSAA",surface);
    if (format != 0u && format != 2u && format != 5u) fail("color format",format);
    if (blend && (resolve || format != 2u)) fail("blend target/resolve",info);
    const uint32_t swap = (info >> 9) & 3u;
    /* Ford SYNC 2 librenderboy.dll: 0x41CDB4B0-0x41CDB500 (format/swap),
       0x41CDBF4C-0x41CDBF90; libGLESv2.dll: 0x41BEE2FC (RGBA4444). */
    if ((info & 0x180u) != 0 || (swap > 1u && !(format == 0u && swap == 3u))) fail("endian/swap",info);
    const bool nonlinear = (info & 0x40u) == 0;
    /* NXP a1638da9 gsl_yamato.c:36-56, mapping_mode=0, range=gpu_base>>14. */
    if (nonlinear && reg(0xF02) != 3u) fail("GMEM configuration",reg(0xF02));
    const bool gmem = nonlinear && (info & 0xFFFFF000u) < gmem_.size();
    const bool tiled = nonlinear && !gmem;
    if (tiled && (surface & 31u)) fail("tiled target pitch",surface);
    const uint32_t binding = info & 0xFFFFF00Fu;
    if (gmem) {
        if (swap == 3u) fail("GMEM swap",info);
        if ((mmu_config & 1u) && mmu_config != 1u) fail("GMEM MMU mode",mmu_config);
        if (gmem_binding_ != 0xFFFFFFFFu && (gmem_binding_ != binding || gmem_pitch_ != (surface & 0x3FFFu)))
            fail("GMEM format/pitch/base reinterpretation",info);
    }
    if (resolve && (!gmem || gmem_binding_ == 0xFFFFFFFFu)) fail("uninitialized resolve source",info);
    const uint32_t pitch = surface & 0x3FFFu, bytes = format == 5u ? 4u : 2u;
    /* NXP a1638da9 yamato_registers.h: RB_DEPTH_INFO; yamato_enum.h: DEPTHX_16;
       Ford SYNC 2 librenderboy.dll: 0x41CDA5A4, 0x41CDB6E8-0x41CDB778. */
    const uint32_t depth_info = depth_enabled ? reg(0x2002) : 0;
    const uint32_t depth_base = depth_info & 0xFFFFF000u;
    if (depth_enabled && (!gmem || bytes != 2u || (depth_info & 0xFFFu) != 0 ||
        depth_base >= gmem_.size() || depth_base % (pitch * 2u) != 0))
        fail("depth attachment",depth_info);
    uint32_t color_mask = reg(0x2104), target_info = info, target_pitch = pitch, offset_x = 0, offset_y = 0;
    uint32_t target_base = info & 0xFFFFF000u;
    /* NXP a1638da9 gsl_drawctxt.c:735-819, build_gmem2sys_cmds;
       Mesa e97ad748 fd2_gmem.c:70-112, emit_gmem2mem_surf. */
    if (resolve) {
        const uint32_t copy = reg(0x231B), offset = reg(0x231C);
        const uint32_t copy_control = reg(0x2318);
        const char* invalid = copy_control != 0u ? "resolve sample/clear control" :
            (copy & 7u) ? "resolve destination endian" : !(copy & 8u) ? "resolve tiled destination" :
            ((copy >> 4) & 15u) != format ? "resolve format conversion" :
            ((copy >> 8) & 3u) > 1u ? "resolve destination swap" :
            ((info >> 9) & 3u) > 1u ? "resolve source swap" :
            (copy & 0xFFFFFC00u & ~0x3C000u) ? "resolve destination dither/reserved" : nullptr;
        if (invalid) fail(invalid,copy);
        if (offset & 0xFC000000u) fail("resolve offset",offset);
        target_base = reg(0x2319); target_pitch = reg(0x231A) * 32u;
        if ((target_base & 4095u) || reg(0x231A) > 511u || !target_pitch) fail("resolve destination",target_base);
        color_mask = (copy >> 14) & 15u; target_info = (copy & 0x300u) << 1;
        offset_x = offset & 8191u; offset_y = (offset >> 13) & 8191u;
    }
    if ((color_mask & ~15u) != 0) fail("color mask",color_mask);
    const uint32_t vtx = reg(0x2302);
    if (vtx != 5u) fail("pixel center/quantization",vtx);
    struct Point { double x, y, inverse_w, z; };
    std::array<Point,3> points{};
    /* NXP a1638da9 yamato_registers.h: PA_CL_VTE_CNTL;
       Ford SYNC 2 librenderboy.dll: 0x41CD2628-0x41CD2648. */
    auto window_depth = [&](const Imx51Gpu3dVec4& p) {
        double z = p[2] * ((vte & 0x200u) ? 1.0 : 1.0 / p[3]);
        if (vte & 0x10u) z *= std::bit_cast<float>(reg(0x2113));
        if (vte & 0x20u) z += std::bit_cast<float>(reg(0x2114));
        return z;
    };
    const double original_depth = depth_enabled ? window_depth(depth_vertices[0].exports[62]) : 0.0;
    const bool constant_depth = !depth_enabled ||
        (original_depth == window_depth(depth_vertices[1].exports[62]) &&
         original_depth == window_depth(depth_vertices[2].exports[62]));
    for (unsigned i = 0; i < 3; ++i) {
        const auto& p = vertices[i].exports[62];
        if (!std::isfinite(p[0]) || !std::isfinite(p[1]) || !std::isfinite(p[2]) ||
            !std::isfinite(p[3]) || (vte != 0xB00u && p[3] <= 0.0f)) fail("homogeneous clipping",i);
        /* NXP a1638da9 gsl_drawctxt.c:731, premultiplied XY/Z; native VTE=30F, W=1. */
        if (vte == 0x30Fu && p[3] != 1.0f) fail("premultiplied nonunit W",i);
        if (vte == 0xB00u && !resolve && p[3] != 1.0f) fail("window-space nonunit W",i);
        const double inverse_w = vte == 0xB00u ? 1.0 : vte == 0x30Fu ? 1.0 : 1.0 / p[3];
        const double xy_scale = (vte == 0x43Fu || vte == 0x40Fu) ? inverse_w : 1.0;
        const double x = vte == 0xB00u ? p[0] : p[0] * xy_scale * std::bit_cast<float>(reg(0x210F)) + std::bit_cast<float>(reg(0x2110));
        const double y = vte == 0xB00u ? p[1] : p[1] * xy_scale * std::bit_cast<float>(reg(0x2111)) + std::bit_cast<float>(reg(0x2112));
        if (!std::isfinite(x) || !std::isfinite(y) || std::abs(x) > 32768 || std::abs(y) > 32768)
            fail("viewport coordinate range",i);
        double z = 0;
        if (depth_enabled) {
            z = constant_depth ? original_depth : window_depth(p);
            if (!std::isfinite(z) || z < 0.0 || z > 1.0)
                fail("out-of-range depth",std::bit_cast<uint32_t>(static_cast<float>(z)));

        }
        points[i] = {std::nearbyint(x * 16.0) / 16.0,std::nearbyint(y * 16.0) / 16.0,inverse_w,z};
    }
    auto edge = [](const Point& a, const Point& b, double x, double y) {
        return (b.x-a.x)*(y-a.y)-(b.y-a.y)*(x-a.x);
    };
    double area = edge(points[0],points[1],points[2].x,points[2].y);
    if (area == 0.0) return;
    /* NXP a1638da9 yamato_registers.h:373-377, PA_SU_SC_MODE_CNTL;
       Khronos OpenGL ES 2.0 section 3.5.1, polygon rasterization. */
    const bool front = (area > 0.0) == ((raster & 4u) != 0);
    if (raster & (front ? 1u : 2u)) return;
    const double sign = area < 0.0 ? -1.0 : 1.0;
    area *= sign;
    const uint32_t offset = reg(0x2080), window_tl = reg(0x2081), window_br = reg(0x2082);
    auto signed15 = [](uint32_t x) { return static_cast<int>((x & 0x7FFFu) ^ 0x4000u) - 0x4000; };
    const int ox = (raster & 0x10000u) ? signed15(offset) : 0;
    const int oy = (raster & 0x10000u) ? signed15(offset >> 16) : 0;
    for (auto& p : points) { p.x += ox; p.y += oy; }
    const int wx = (window_tl & 0x80000000u) ? 0 : ox, wy = (window_tl & 0x80000000u) ? 0 : oy;
    const uint32_t screen_tl = reg(0x200E), screen_br = reg(0x200F);
    int left = (std::max)(int(screen_tl & 0x7FFFu),int(window_tl & 0x7FFFu)+wx);
    int top = (std::max)(int((screen_tl >> 16) & 0x7FFFu),int((window_tl >> 16) & 0x7FFFu)+wy);
    int right = (std::min)(int(screen_br & 0x7FFFu),int(window_br & 0x7FFFu)+wx);
    int bottom = (std::min)(int((screen_br >> 16) & 0x7FFFu),int((window_br >> 16) & 0x7FFFu)+wy);
    left = (std::max)(left,int(std::floor((std::min)({points[0].x,points[1].x,points[2].x}))));
    top = (std::max)(top,int(std::floor((std::min)({points[0].y,points[1].y,points[2].y}))));
    right = (std::min)(right,int(std::ceil((std::max)({points[0].x,points[1].x,points[2].x}))));
    bottom = (std::min)(bottom,int(std::ceil((std::max)({points[0].y,points[1].y,points[2].y}))));
    if (left >= right || top >= bottom || (color_mask == 0 && !depth_write)) return;
    if (left < 0 || top < 0 || right > static_cast<int>(pitch)) fail("target bounds",pitch);
    if (!resolve && pixel_program.empty()) fail("missing pixel shader",0);
    const uint64_t extent = (uint64_t(bottom-1)*pitch+right)*bytes;
    const uint64_t base = info & 0xFFFFF000u;
    if (gmem && base+extent > gmem_.size()) fail("GMEM capacity",static_cast<uint32_t>(base));
    if (depth_enabled && uint64_t(depth_base)+(uint64_t(bottom-1)*pitch+right)*2u > gmem_.size())
        fail("depth GMEM capacity",depth_base);
    if (depth_enabled && color_mask && base+extent > uint64_t(depth_base)+(uint64_t(top)*pitch+left)*2u &&
        uint64_t(depth_base)+(uint64_t(bottom-1)*pitch+right)*2u > base+(uint64_t(top)*pitch+left)*bytes)
        fail("overlapping depth/color attachments",depth_base);
    /* NXP a1638da9 gsl_drawctxt.c:787-800, build_gmem2sys_cmds: COPY_DEST_OFFSET is the page-alignment pixel remainder. */
    auto* target = tiled ? nullptr : gmem && !resolve ? gmem_.data()+base : emu_.Get<Imx51Gpu3dMemory>().WriteSpan(target_base,
        (uint64_t(bottom-1+offset_y)*target_pitch+right+offset_x)*bytes,mmu_config);
    auto top_left = [&](const Point& a, const Point& b) {
        const double dx = (b.x-a.x)*sign, dy = (b.y-a.y)*sign;
        return dy < 0.0 || (dy == 0.0 && dx > 0.0);
    };
    for (int y = top; y < bottom; ++y) for (int x = left; x < right; ++x) {
        const double a = edge(points[1],points[2],x+0.5,y+0.5)*sign;
        const double b = edge(points[2],points[0],x+0.5,y+0.5)*sign;
        const double c = edge(points[0],points[1],x+0.5,y+0.5)*sign;
        if (a < 0 || b < 0 || c < 0 || (a == 0 && !top_left(points[1],points[2])) ||
            (b == 0 && !top_left(points[2],points[0])) || (c == 0 && !top_left(points[0],points[1]))) continue;
        std::array<double,3> weights{a/area,b/area,c/area};
        /* Khronos OpenGL ES 2.0.25 section 3.5.1: window-z linear interpolation;
           Ford SYNC 2 RUN_20260906_174030_00 F067-F090, F097-F100, F113-F132: depth16 conversion. */
        const double depth = constant_depth ? original_depth :
            weights[0]*points[0].z + weights[1]*points[1].z + weights[2]*points[2].z;
        const uint16_t incoming_depth = static_cast<uint16_t>((std::min)(65535.0,std::floor(depth * 65536.0)));
        auto* depth_destination = depth_enabled ? gmem_.data()+depth_base+(uint64_t(y)*pitch+x)*2u : nullptr;
        if ((raster & 0x100000u) == 0) {
            double total = 0;
            for (unsigned i = 0; i < 3; ++i) { weights[i] *= points[i].inverse_w; total += weights[i]; }
            for (auto& weight : weights) weight /= total;
        }
        Imx51Gpu3dVec4 color{};
        if (resolve) {
            const auto* p = gmem_.data()+base+(uint64_t(y)*pitch+x)*bytes;
            if (bytes == 4u) for (unsigned i=0;i<4;++i) color[i]=float(p[i])/255.0f;
            else {
                const uint32_t packed=uint32_t(p[0])|(uint32_t(p[1])<<8);
                if (format == 0u) for (unsigned i=0;i<4;++i) color[i]=float((packed>>(i*4u))&15u)/15.0f;
                else color={float(packed&31u)/31.0f,float((packed>>5)&63u)/63.0f,float((packed>>11)&31u)/31.0f,1.0f};
            }
            /* Mesa e97ad748 a2xx.xml: RB_COLOR_INFO.SWAP; Navigation20260906_235040 source_info=202. */
            if (swap == 1u) std::swap(color[0],color[2]);
        } else {
            std::array<Imx51Gpu3dShaderState, 4> fragments{};
            const unsigned pixel_lane = unsigned(y & 1) * 2u + unsigned(x & 1);
            auto& fragment = fragments[pixel_lane];
            const uint64_t varyings = vertices[0].export_mask & vertices[1].export_mask & vertices[2].export_mask;
            for (unsigned slot = 0; slot < 32; ++slot) if (varyings & (uint64_t{1} << slot))
                for (unsigned component = 0; component < 4; ++component)
                    for (unsigned i = 0; i < 3; ++i)
                        fragment.registers[slot][component] += static_cast<float>(weights[i]*vertices[i].exports[slot][component]);
            /* Khronos GLES 2.0.25 section 3.7.7, texture-coordinate derivatives; GLSL ES 1.00 section 8.8. */
            std::array<std::array<double,3>,4> quad_weights{};
            bool gradients_valid = true;
            for (unsigned lane = 0; lane < 4u; ++lane) {
                const double qx = (x & ~1) + (lane & 1u) + 0.5;
                const double qy = (y & ~1) + (lane >> 1) + 0.5;
                auto& q = quad_weights[lane];
                q = {edge(points[1],points[2],qx,qy)*sign/area,
                     edge(points[2],points[0],qx,qy)*sign/area,
                     edge(points[0],points[1],qx,qy)*sign/area};
                if ((raster & 0x100000u) == 0) {
                    double total = 0;
                    for (unsigned i = 0; i < 3u; ++i) { q[i] *= points[i].inverse_w; total += q[i]; }
                    if (!std::isfinite(total) || total == 0) { gradients_valid = false; continue; }
                    for (auto& weight : q) weight /= total;
                }
            }
            fragment.gradient_mask = gradients_valid ? varyings & 0xFFFFFFFFu : 0;
            for (unsigned slot = 0; slot < 32u; ++slot) if (fragment.gradient_mask & (uint64_t{1} << slot))
                for (unsigned component = 0; component < 4u; ++component) {
                    std::array<float,4> q{};
                    for (unsigned lane = 0; lane < 4u; ++lane)
                        for (unsigned i = 0; i < 3u; ++i)
                            q[lane] += static_cast<float>(quad_weights[lane][i]*vertices[i].exports[slot][component]);
                    for (unsigned lane = 0; lane < 4u; ++lane)
                        if (lane != pixel_lane) fragments[lane].registers[slot][component] = q[lane];
                    fragment.gradients_x[slot][component] = q[(y & 1)*2+1] - q[(y & 1)*2];
                    fragment.gradients_y[slot][component] = q[(x & 1)+2] - q[x & 1];
                }
            // Extrapolated lanes are helpers only: only pixel_lane is committed below.
            if (gradients_valid)
                emu_.Get<Imx51Gpu3dShader>().RunQuad(pixel_program,registers,mmu_config,fragments);
            else
                emu_.Get<Imx51Gpu3dShader>().Run(pixel_program,true,registers,mmu_config,fragment);
            if (!fragment.memory_exports.empty()) fail("pixel memory export",0);
            if (fragment.killed) continue;
            if (depth_enabled && (fragment.export_mask & ~uint64_t{1}))
                fail("depth fragment exports",static_cast<uint32_t>(fragment.export_mask));
            /* NXP a1638da9 yamato_enum.h: CompareFrag; Khronos GLES 2.0 glDepthFunc. */
            if (depth_enabled) {
                const uint32_t stored = uint32_t(depth_destination[0]) | (uint32_t(depth_destination[1]) << 8);
                const bool passes[] = {false,incoming_depth < stored,incoming_depth == stored,incoming_depth <= stored,
                    incoming_depth > stored,incoming_depth != stored,incoming_depth >= stored,true};
                if (!passes[(depth_control >> 4) & 7u]) continue;
            }
            if (depth_write) writes.pixels.push_back({depth_destination,
                {static_cast<uint8_t>(incoming_depth),static_cast<uint8_t>(incoming_depth >> 8),0,0},2});
            if (color_mask == 0) continue;
            if ((fragment.export_mask & 1u) == 0) fail("missing fragment color",0);
            color = fragment.exports[0];
        }
        for (auto& channel : color) {
            if (!std::isfinite(channel)) fail("nonfinite fragment",0);
            channel = std::clamp(channel,0.0f,1.0f);
        }
        const uint64_t address = (uint64_t(y+offset_y)*target_pitch+x+offset_x)*bytes;
        auto* destination = tiled ? emu_.Get<Imx51Gpu3dMemory>().WriteSpan(
            Imx51Gpu3dTiledAddress(target_base,target_pitch,bytes,uint32_t(x),uint32_t(y)),bytes,mmu_config) : target+address;
        RasterWrites::Pixel pixel{destination,{},bytes};
        if (((target_info >> 9) & 3u) == 1u) std::swap(color[0],color[2]);
        uint32_t mask = color_mask;
        if (((target_info >> 9) & 3u) == 1u) mask = (mask & 10u) | ((mask & 1u) << 2) | ((mask & 4u) >> 2);
        /* OpenGL ES 2.0.25 section 4.1.7; NXP a1638da9 RB_COLOR_INFO.COLOR_ROUND_MODE;
           AMD Z430 GLES2: RGBA8888, round mode 0, disabled-dither color readback. */
        const bool truncate_8888 = (target_info & 0x30u) == 0u && (resolve || dither_mode == 0u);
        if (bytes == 4u) for (unsigned i = 0; i < 4; ++i)
            pixel.data[i] = (mask & (1u << i)) ? static_cast<uint8_t>(truncate_8888 ? color[i] * 255u :
                ApproximateDitherQuantize(color[i],255u,i,uint32_t(x)+offset_x,uint32_t(y)+offset_y,
                    !resolve && dither_mode != 0u)) : destination[i];
        else {
            uint32_t packed = uint32_t(destination[0]) | (uint32_t(destination[1]) << 8);
            const std::array<uint32_t,4> shifts = format == 0u ?
                (((target_info >> 9) & 3u) == 3u ? std::array<uint32_t,4>{12,8,4,0} : std::array<uint32_t,4>{0,4,8,12}) :
                std::array<uint32_t,4>{0,5,11,0};
            const std::array<uint32_t,4> maxima = format == 0u ? std::array<uint32_t,4>{15,15,15,15} : std::array<uint32_t,4>{31,63,31,0};
            /* NXP a1638da9 BlendOpX: SRC_ALPHA/ONE_MINUS_SRC_ALPHA; CombFuncX: DST_PLUS_SRC. */
            if (blend) for (unsigned i = 0; i < 3u; ++i) {
                const float stored = static_cast<float>((packed >> shifts[i]) & maxima[i]) / maxima[i];
                color[i] = color[i] * color[3] + stored * (1.0f - color[3]);
            }
            for (unsigned i = 0; i < (format == 0u ? 4u : 3u); ++i) if (mask & (1u << i))
                packed = (packed & ~(maxima[i] << shifts[i])) | (ApproximateDitherQuantize(color[i],maxima[i],i,
                    uint32_t(x)+offset_x,uint32_t(y)+offset_y,!resolve && dither_mode != 0u) << shifts[i]);
            pixel.data[0] = static_cast<uint8_t>(packed); pixel.data[1] = static_cast<uint8_t>(packed >> 8);
        }
        writes.pixels.push_back(pixel);
    }
    if (gmem && !resolve && !writes.pixels.empty()) { writes.binding = binding; writes.pitch = pitch; }
}
