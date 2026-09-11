#include "imx51_gpu3d_shader.h"
#include "imx51_gpu3d_memory.h"
#include "imx51_gpu3d_texture.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../boards/board_context.h"
#include <algorithm>
#include <bit>
#include <cmath>
#include <limits>

REGISTER_SERVICE(Imx51Gpu3dShader);
bool Imx51Gpu3dShader::ShouldRegister() {
    auto* board = emu_.TryGet<BoardContext>();
    return board && board->GetSoc() == SocFamily::iMX51;
}
void Imx51Gpu3dShader::Reject(const char* reason, uint32_t value) {
    emu_.Get<Fatal>().Die("GPU shader rejected %s (0x%08X)", reason, value);
}
uint32_t Imx51Gpu3dShader::Register(const std::unordered_map<uint32_t, uint32_t>& regs, uint32_t index) {
    auto it = regs.find(index);
    if (it == regs.end()) Reject("unprogrammed register", index);
    return it->second;
}

/* Mesa e97ad748 instr-a2xx.h: instr_alu_t; disasm-a2xx.c: print_srcreg;
   ir2_assemble.c: alu_swizzle_scalar, alu_swizzle_scalar2, src_reg_byte;
   ir2_nir.c: emit_alu, store_output, extra_position_exports;
   ir2_assemble.c: relative_addr on export32; fd2_gmem.c: binning export constants. */
void Imx51Gpu3dShader::Alu(std::array<uint32_t, 3> w, bool pixel,
                          const std::unordered_map<uint32_t, uint32_t>& regs,
                          Imx51Gpu3dShaderState& state, bool& predicate, float& previous) {
    const uint32_t pred = (w[1] >> 27) & 3u;
    if (pred == 1u) Reject("ALU predicate selection", pred);
    if (pred && predicate != ((pred & 1u) != 0)) return;
    // Snapshot addressing before either paired slot can update MOVA state.
    const int32_t old_address = state.address_register, loop_address = state.loop_address;
    auto temporary_index = [&](uint32_t index, bool relative) {
        const int64_t effective = int64_t(index) + (relative ? loop_address : 0);
        if (effective < 0 || effective >= 64) Reject("ALU register extent", static_cast<uint32_t>(effective));
        return static_cast<uint32_t>(effective);
    };
    auto source = [&](uint32_t which, bool force_constant = false) {
        const uint32_t shift = (3u - which) * 8u;
        const uint32_t index = (w[2] >> shift) & 255u;
        const bool temporary = !force_constant && ((w[2] >> (32u - which)) & 1u) != 0;
        Imx51Gpu3dVec4 raw{}, result{};
        if (temporary) {
            raw = state.registers[temporary_index(index & 63u, (index & 64u) != 0)];
            if (index & 128u) for (auto& value : raw) value = std::abs(value);
        } else {
            // Related Xenia model: first constant uses const_0_rel_abs; later
            // constant operands share const_1_rel_abs. A2xx has the same fields.
            const bool first = which == 1u || (which == 2u ? (w[2] & 0x80000000u) != 0 : (w[2] & 0xC0000000u) == 0xC0000000u);
            const bool relative = ((w[1] >> (first ? 31u : 30u)) & 1u) != 0;
            const bool use_address = (w[1] & 0x20000000u) != 0;
            // Keep Mesa's special absolute export32 constant base workaround.
            const bool export32 = (w[0] & 0x803Fu) == 0x8020u && use_address && !relative;
            const uint32_t base = export32 ? 0u : Register(regs, pixel ? 0x2308u : 0x2307u) & 511u;
            const int64_t effective = int64_t(base) + index + (relative ? (use_address ? old_address : loop_address) : 0);
            if (effective < 0 || effective >= 512) Reject("constant extent", static_cast<uint32_t>(effective));
            for (uint32_t i = 0; i < 4u; ++i) raw[i] = std::bit_cast<float>(Register(regs, 0x4000u + static_cast<uint32_t>(effective) * 4u + i));
        }
        const uint32_t swizzle = (w[1] >> shift) & 255u;
        const bool negate = ((w[1] >> (27u - which)) & 1u) != 0;
        for (uint32_t i = 0; i < 4u; ++i) result[i] = raw[((swizzle >> (i * 2u)) + i) & 3u] * (negate ? -1.0f : 1.0f);
        return result;
    };
    const uint32_t vm = (w[0] >> 16) & 15u, sm = (w[0] >> 20) & 15u;
    const uint32_t vector_op = (w[2] >> 24) & 31u, scalar_op = w[0] >> 26;
    /* Mesa instr-a2xx.h: reserved encodings and compiler-only NONE sentinels.
       Validate before reading operands, but preserve unused zero-mask halves. */
    if (vm) {
        if (vector_op == 31u) Reject("active VECTOR_NONE", vector_op);
        if (vector_op == 30u) Reject("reserved vector opcode", vector_op);
    }
    if (sm) {
        if (scalar_op == 63u) Reject("active SCALAR_NONE", scalar_op);
        if (scalar_op == 41u || scalar_op > 50u) Reject("reserved scalar opcode", scalar_op);
    }
    if (vector_op == 29u && (scalar_op == 23u || scalar_op == 24u))
        Reject("simultaneous address writes", scalar_op);
    if (!pixel && ((vector_op >= 24u && vector_op <= 27u) || (scalar_op >= 35u && scalar_op <= 39u)))
        Reject("vertex kill opcode", vector_op >= 24u && vector_op <= 27u ? vector_op : scalar_op);
    // Match Xenia ProcessAluInstruction: both slots use entry predication;
    // scalar predicate writes follow vector writes and win when both are present.
    auto compare = [](uint32_t op, float a, float b) {
        return op == 0u ? a == b : op == 1u ? a != b : op == 2u ? a > b : a >= b;
    };
    auto address = [](float value, bool round) {
        // MOVA conversion follows the related Xenia kMaxAs/kMaxAsf model.
        // Saturate before casting, including NaN, to avoid host conversion UB.
        const float integral = std::floor(value + (round ? 0.5f : 0.0f));
        return !(integral >= -256.0f) ? -256 : integral > 255.0f ? 255 : static_cast<int32_t>(integral);
    };
    auto multiply = [](float a, float b) {
        // Xenia ucode.h: legacy multiply, citing R5xx 8.7.5 and Adreno 200 tests.
        // Zero/subnormal inputs produce +0 even when the other input is NaN/Inf.
        if (std::abs(a) < std::numeric_limits<float>::min() ||
            std::abs(b) < std::numeric_limits<float>::min()) return 0.0f;
        return a * b;
    };
    Imx51Gpu3dVec4 vector{};
    float scalar = previous;
    /* NXP yamato_enum.h: PRED_SETE_PUSHv..KILLNEv; Mesa ir2_ra.c: has_side_effects;
       Xenia ucode.h: AluVectorOpcode::kSetpEqPush..kKillNe. */
    if (vm || vector_op == 29u || (vector_op >= 20u && vector_op <= 27u)) {
        const auto a = source(1u), b = (vector_op >= 8u && vector_op <= 10u) || vector_op == 19u || (vector_op == 29u && !vm) ? Imx51Gpu3dVec4{} : source(2u);
        const uint32_t op = (w[2] >> 24) & 31u;
        Imx51Gpu3dVec4 c{};
        if ((op >= 11u && op <= 14u) || op == 17u) c = source(3u);
        if (op == 18u) {
            // Mesa ir2_nir.c emits direction.zzxy, direction.yxzz and consumes
            // (T, S, 2*major, face). The axis/tie formula follows Xenia kCube;
            // arbitrary operand pairs and nonfinite directions remain unsupported.
            const float x = a[2], y = a[3], z = a[0];
            if (a[1] != z || b[0] != y || b[1] != x || b[2] != z || b[3] != z)
                Reject("cube operand layout", w[1]);
            if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(z) ||
                (x == 0.0f && y == 0.0f && z == 0.0f))
                Reject("cube direction", w[1]);
            if (std::abs(z) >= std::abs(x) && std::abs(z) >= std::abs(y))
                vector = {-y, z < 0.0f ? -x : x, 2.0f * z, z < 0.0f ? 5.0f : 4.0f};
            else if (std::abs(y) >= std::abs(x))
                vector = {y < 0.0f ? -z : z, x, 2.0f * y, y < 0.0f ? 3.0f : 2.0f};
            else
                vector = {-y, x < 0.0f ? z : -z, 2.0f * x, x < 0.0f ? 1.0f : 0.0f};
        }
        float dot = 0;
        if (op == 15u || op == 16u || op == 17u) {
            const uint32_t count = op == 15u ? 4u : op == 16u ? 3u : 2u;
            for (uint32_t i = 0; i < count; ++i) dot += multiply(a[i], b[i]);
            // Xenia kDp2Add/MSDN model: XY dot plus post-swizzle C.x.
            // Mesa fdot2 uses a zero addend, which alone cannot distinguish lanes.
            if (op == 17u) dot += c[0];
        }
        for (uint32_t i = 0; i < 4u; ++i) {
            switch (op) {
            case 0: vector[i] = a[i] + b[i]; break;
            case 1: vector[i] = multiply(a[i], b[i]); break;
            case 2: vector[i] = std::fmax(a[i], b[i]); break;
            case 3: vector[i] = std::fmin(a[i], b[i]); break;
            case 4: vector[i] = a[i] == b[i] ? 1.0f : 0.0f; break;
            case 5: vector[i] = a[i] > b[i] ? 1.0f : 0.0f; break;
            case 6: vector[i] = a[i] >= b[i] ? 1.0f : 0.0f; break;
            case 7: vector[i] = a[i] != b[i] ? 1.0f : 0.0f; break;
            case 8: vector[i] = a[i] - std::floor(a[i]); break;
            case 9: vector[i] = std::trunc(a[i]); break;
            case 10: vector[i] = std::floor(a[i]); break;
            case 11: vector[i] = multiply(a[i], b[i]) + c[i]; break;
            case 12: vector[i] = a[i] == 0 ? b[i] : c[i]; break;
            case 13: vector[i] = a[i] >= 0 ? b[i] : c[i]; break;
            case 14: vector[i] = a[i] > 0 ? b[i] : c[i]; break;
            case 15: case 16: case 17: vector[i] = dot; break;
            case 18: break;
            /* NXP yamato_enum.h: MAX4v; Xenia ucode.h: AluVectorOpcode::kMax4. */
            case 19:
                vector[i] = a[0] > a[1] && a[0] > a[2] && a[0] > a[3] ? a[0]
                    : a[1] > a[2] && a[1] > a[3] ? a[1] : a[2] > a[3] ? a[2] : a[3]; break;
            case 20: case 21: case 22: case 23:
                predicate = a[3] == 0.0f && compare(op - 20u, b[3], 0.0f);
                vector[i] = a[0] == 0.0f && compare(op - 20u, b[0], 0.0f) ? 0.0f : a[0] + 1.0f;
                break;
            case 24: case 25: case 26: case 27: {
                const uint32_t comparison = op == 24u ? 0u : op == 25u ? 2u : op == 26u ? 3u : 1u;
                bool kill = false;
                for (uint32_t lane = 0; lane < 4u; ++lane) kill |= compare(comparison, a[lane], b[lane]);
                state.killed |= kill;
                vector[i] = kill ? 1.0f : 0.0f;
                break;
            }
            /* NXP yamato_enum.h: DSTv; Xenia ucode.h: AluVectorOpcode::kDst. */
            case 28: vector[i] = i == 0u ? 1.0f : i == 1u ? multiply(a[1], b[1]) : i == 2u ? a[2] : b[3]; break;
            // Mesa names MOVAv but does not lower it. Use the related Xenia
            // MAXA model: a0 comes from A.w, result is per-lane max(A, B).
            case 29: state.address_register = address(a[3], true); vector[i] = std::fmax(a[i], b[i]); break;
            default: Reject("vector opcode", op);
            }
        }
    }
    /* Mesa ir2_ra.c: has_side_effects; Xenia ucode.h: AluScalarOpcodeInfo. */
    if (sm || scalar_op == 23u || scalar_op == 24u || (scalar_op >= 27u && scalar_op <= 39u)) {
        const bool constant_op = scalar_op >= 42u && scalar_op <= 47u;
        const auto c = scalar_op == 33u || scalar_op == 50u ? Imx51Gpu3dVec4{} : source(3u, constant_op);
        const float a = c[3];
        float b = c[2];
        if (constant_op) {
            // Xenia scalar_const_reg_op_src_temp_reg / ParseAluInstruction:
            // A2xx shares these opcode/operand fields. Source 3 is the full-byte
            // constant index; opcode bit 0, src3_sel and swizzle bits 2..5 name R.
            // This special form uses constant W and temporary X swizzle fields.
            const uint32_t swizzle = w[1] & 255u;
            const uint32_t index = (scalar_op & 1u) | (((w[2] >> 29) & 1u) << 1) | (swizzle & 60u);
            b = state.registers[index][swizzle & 3u];
            if (w[1] & 0x1000000u) b = -b;
        }
        const uint32_t op = w[0] >> 26;
        switch (op) {
        case 0: scalar = a + b; break;
        case 1: scalar = a + previous; break;
        case 2: scalar = multiply(a, b); break;
        case 3: scalar = multiply(a, previous); break;
        /* NXP yamato_enum.h: MUL_PREV2s; Xenia ucode.h: AluScalarOpcode::kMulsPrev2. */
        case 4:
            scalar = previous == -std::numeric_limits<float>::max() || !std::isfinite(previous) || !std::isfinite(b) || b <= 0.0f
                ? -std::numeric_limits<float>::max() : multiply(a, previous); break;
        case 5: scalar = std::fmax(a, b); break;
        case 6: scalar = std::fmin(a, b); break;
        /* NXP yamato_enum.h: SETEs..SETNEs; Xenia ucode.h: AluScalarOpcode::kSeqs..kSnes. */
        case 7: case 8: case 9: case 10:
            scalar = compare(op == 7u ? 0u : op == 8u ? 2u : op == 9u ? 3u : 1u, a, 0.0f) ? 1.0f : 0.0f; break;
        case 11: scalar = a - std::floor(a); break;
        case 12: scalar = std::trunc(a); break;
        case 13: scalar = std::floor(a); break;
        case 14: scalar = std::exp2(a); break;
        /* Xenia ucode.h: AluScalarOpcode::kLogc, kRcpf, kRsqc, kRsqf. */
        case 15:
            scalar = std::log2(a);
            if (scalar == -std::numeric_limits<float>::infinity()) scalar = -std::numeric_limits<float>::max();
            break;
        case 16: scalar = std::log2(a); break;
        case 17: scalar = std::clamp(1.0f / a, -std::numeric_limits<float>::max(), std::numeric_limits<float>::max()); break;
        case 18: scalar = 1.0f / a; if (std::isinf(scalar)) scalar = std::copysign(0.0f, scalar); break;
        case 19: scalar = 1.0f / a; break;
        case 20: scalar = std::clamp(1.0f / std::sqrt(a), -std::numeric_limits<float>::max(), std::numeric_limits<float>::max()); break;
        case 21: scalar = 1.0f / std::sqrt(a); if (std::isinf(scalar)) scalar = std::copysign(0.0f, scalar); break;
        case 22: scalar = 1.0f / std::sqrt(a); break;
        case 23: state.address_register = address(a, true); scalar = std::fmax(a, b); break;
        case 24: state.address_register = address(a, false); scalar = std::fmax(a, b); break;
        case 25: scalar = a - b; break;
        case 26: scalar = a - previous; break;
        /* NXP yamato_enum.h: PRED_SETEs..KILLONEs; Mesa ir2_nir.c: emit_if;
           Xenia ucode.h: AluScalarOpcode::kSetpEq..kKillsOne. */
        case 27: case 28: case 29: case 30:
            predicate = compare(op - 27u, a, 0.0f); scalar = predicate ? 0.0f : 1.0f; break;
        case 31: predicate = a == 1.0f; scalar = predicate ? 0.0f : a == 0.0f ? 1.0f : a; break;
        case 32: scalar = a - 1.0f; predicate = scalar <= 0.0f; if (predicate) scalar = 0.0f; break;
        case 33: predicate = false; scalar = std::numeric_limits<float>::max(); break;
        case 34: predicate = a == 0.0f; scalar = a; break;
        case 35: case 36: case 37: case 38: case 39: {
            const bool kill = op == 39u ? a == 1.0f : compare(op == 35u ? 0u : op == 36u ? 2u : op == 37u ? 3u : 1u, a, 0.0f);
            state.killed |= kill; scalar = kill ? 1.0f : 0.0f; break;
        }
        case 40: scalar = std::sqrt(a); break;
        case 42: case 43: scalar = multiply(a, b); break;
        case 44: case 45: scalar = a + b; break;
        case 46: case 47: scalar = a - b; break;
        /* Mesa ir2_nir.c: nir_op_fsin, nir_op_fcos; Xenia ucode.h: kSin, kCos. */
        case 48: scalar = std::sin(a); break;
        case 49: scalar = std::cos(a); break;
        case 50: break;
        default: Reject("scalar opcode", op);
        }
        previous = scalar;
    }
    auto write = [&](uint32_t index, uint32_t mask, const Imx51Gpu3dVec4& values, bool clamp, bool relative) {
        if (!mask) return;
        const bool output = (w[0] & 0x8000u) != 0;
        if (output && state.killed) return;
        if (output && relative) Reject("relative ALU export", index);
        if (!output) index = temporary_index(index, relative);
        if (output && index >= 34u && index < 62u) Reject("memory export register", index);
        if (!output) state.gradient_mask &= ~(uint64_t{1} << index);
        auto& target = output ? state.exports[index] : state.registers[index];
        for (uint32_t i = 0; i < 4u; ++i) if ((mask >> i) & 1u) target[i] = clamp ? std::clamp(values[i], 0.0f, 1.0f) : values[i];
        if (output) state.export_mask |= uint64_t(1) << index;
        if (output && index == 33u) {
            if (!(state.export_mask & (uint64_t(1) << 32)) || mask != 15u) Reject("incomplete memory export", mask);
            state.memory_exports.push_back({state.exports[32], state.exports[33]});
        }
    };
    write(w[0] & 63u, vm, vector, ((w[0] >> 24) & 1u) != 0, (w[0] & 64u) != 0);
    write((w[0] >> 8) & 63u, sm, {scalar, scalar, scalar, scalar}, ((w[0] >> 25) & 1u) != 0, (w[0] & 0x4000u) != 0);
}

/* Mesa e97ad748 instr-a2xx.h: instr_fetch_vtx_t, instr_fetch_tex_t;
   fd2_program.c: patch_vtx_fetch; fd2_emit.c: fd2_emit_vertex_bufs;
   a2xx.xml: a2xx_sq_surfaceformat; NXP yamato_registers.h: TP0_CHICKEN;
   gsl_drawctxt.c: sys2gmem_vtx_pgm, TP0_CHICKEN=0; fd2_emit.c: TP0_CHICKEN=2. */
void Imx51Gpu3dShader::Fetch(std::array<uint32_t, 3> w,
                            const std::unordered_map<uint32_t, uint32_t>& regs,
                            uint32_t config, Imx51Gpu3dShaderState& state, bool predicate) {
    if ((w[1] >> 31) && predicate != ((w[2] >> 31) != 0)) return;
    auto fetch_index = [&](uint32_t shift) {
        const int64_t index = int64_t((w[0] >> shift) & 63u) + (((w[0] >> (shift + 6u)) & 1u) ? state.loop_address : 0);
        if (index < 0 || index >= 64) Reject("fetch register extent", static_cast<uint32_t>(index));
        return static_cast<uint32_t>(index);
    };
    const uint32_t source = fetch_index(5u), destination = fetch_index(12u);
    const auto& input = state.registers[source];
    Imx51Gpu3dVec4 value{};
    const uint32_t op = w[0] & 31u;
    if (op == 24u) {
        // Mesa ir2.c schedule_instrs / ir2_assemble.c: the setter selects one
        // source component and preserves all ordinary destination components.
        // Keep its value for subsequent samples; zero is our invocation default.
        state.texture_lod = input[(w[0] >> 26) & 3u];
        return;
    }
    if (op == 25u || op == 26u) {
        // Provisional Xenos-compatible XYZ gradient register layout; A2xx
        // shares the setter encodings. Missing components begin at zero.
        auto& gradient = op == 25u ? state.texture_gradients_x : state.texture_gradients_y;
        for (uint32_t i = 0; i < 3u; ++i)
            gradient[i] = input[(w[0] >> (26u + i * 2u)) & 3u];
        return;
    }
    if (op == 18u) {
        if ((w[2] & 0x7FFFFFFDu) || (w[1] & 0x60000000u)) Reject("gradient query controls", w[1]);
        if (!(state.gradient_mask & (uint64_t{1} << source))) Reject("unavailable query gradients", w[0]);
        // Provisional Xenos layout: XZ=ddx(source.xy), YW=ddy(source.xy).
        // The quad executor supplies finite differences after coordinate ALU.
        for (uint32_t i = 0; i < 2u; ++i) {
            const uint32_t component = (w[0] >> (26u + i * 2u)) & 3u;
            value[i * 2u] = state.gradients_x[source][component];
            value[i * 2u + 1u] = state.gradients_y[source][component];
        }
    } else if (op == 1u || op == 16u || op == 17u || op == 19u) {
        Imx51Gpu3dVec4 coords{}, dx{}, dy{};
        for (uint32_t i = 0; i < 3u; ++i) {
            const uint32_t component = (w[0] >> (26u + i * 2u)) & 3u;
            coords[i] = input[component];
            dx[i] = state.gradients_x[source][component];
            dy[i] = state.gradients_y[source][component];
        }
        const bool explicit_gradients = (w[2] & 1u) != 0;
        if (explicit_gradients) { dx = state.texture_gradients_x; dy = state.texture_gradients_y; }
        const bool gradients = explicit_gradients || (state.gradient_mask & (uint64_t{1} << source)) != 0;
        value = emu_.Get<Imx51Gpu3dTexture>().Sample(regs, config, (w[0] >> 20) & 31u, coords, w,
            gradients ? &dx : nullptr, gradients ? &dy : nullptr, state.texture_lod);
    } else if (op == 0u) {
        const uint32_t slot = (w[0] >> 20) & 31u, select = (w[0] >> 25) & 3u;
        if (select == 3u) Reject("vertex constant selector", select);
        const uint32_t base = Register(regs, 0x4800u + slot * 6u + select * 2u);
        const uint32_t size = Register(regs, 0x4801u + slot * 6u + select * 2u);
        if ((base & 3u) != 3u) Reject("vertex buffer type", base);
        const float index = input[w[0] >> 30];
        if (!std::isfinite(index) || index < 0 || index >= 4294967296.0f || index != std::floor(index)) Reject("vertex index", std::bit_cast<uint32_t>(index));
        const uint32_t unit = (Register(regs, 0x0E1Eu) & 2u) ? 1u : 4u;
        const uint64_t offset = (uint64_t(static_cast<uint32_t>(index)) * (w[2] & 255u) + ((w[2] >> 8) & 0x3FFFFFu)) * unit;
        const uint32_t format = (w[1] >> 16) & 63u;
        // Mesa fd2_pipe2surface / patch_vtx_fetch: component widths and signed,
        // normalized and fixed-point controls are independent of the surface format.
        uint32_t count = 0, component_bytes = 0;
        bool floating = false;
        switch (format) {
        case 2: count = 1; component_bytes = 1; break;
        case 10: count = 2; component_bytes = 1; break;
        case 6: count = 4; component_bytes = 1; break;
        case 24: case 25: case 26:
            count = 1u << (format - 24u); component_bytes = 2; break;
        case 30: case 31: case 32:
            count = 1u << (format - 30u); component_bytes = 2; floating = true; break;
        case 33: case 34: case 35:
            count = 1u << (format - 33u); component_bytes = 4; break;
        case 36: case 37: case 38: case 57:
            count = format == 57u ? 3u : 1u << (format - 36u);
            component_bytes = 4; floating = true; break;
        default: Reject("vertex format", format);
        }
        const uint32_t bytes = count * component_bytes;
        if (offset + bytes > size) Reject("vertex buffer extent", size);
        const bool signed_components = (w[1] & 0x1000u) != 0;
        const bool normalized = (w[1] & 0x2000u) == 0;
        if (!floating && signed_components && normalized && (w[1] & 0x4000u))
            Reject("vertex signed repeating fraction mode", w[1]);
        const int exponent = int((w[1] >> 24) & 31u) - int((w[1] >> 24) & 32u);
        const uint8_t* data = emu_.Get<Imx51Gpu3dMemory>().ReadSpan(uint64_t(base & ~3u) + offset, bytes, config);
        for (uint32_t i = 0; i < count; ++i) {
            uint32_t packed = 0;
            for (uint32_t j = 0; j < component_bytes; ++j)
                packed |= uint32_t(data[i * component_bytes + j]) << (j * 8u);
            if (floating && component_bytes == 4u) value[i] = std::bit_cast<float>(packed);
            else if (floating) {
                const uint32_t exp = (packed >> 10) & 31u, fraction = packed & 1023u;
                if (exp == 31u) value[i] = std::bit_cast<float>(0x7F800000u | (fraction << 13));
                else value[i] = std::ldexp(float(exp ? fraction + 1024u : fraction), exp ? int(exp) - 25 : -24);
                if (packed & 0x8000u) value[i] = -value[i];
            } else {
                const uint32_t bits = component_bytes * 8u;
                const uint64_t range = uint64_t{1} << bits;
                const int64_t integer = signed_components && (packed & (range >> 1)) ?
                    int64_t(packed) - int64_t(range) : int64_t(packed);
                double converted = double(integer);
                if (normalized) converted = signed_components ?
                    (std::max)(-1.0, converted / double((range >> 1) - 1u)) : converted / double(range - 1u);
                value[i] = static_cast<float>(converted);
            }
            value[i] = std::ldexp(value[i], exponent);
        }
    } else Reject("fetch opcode", op);
    state.gradient_mask &= ~(uint64_t{1} << destination);
    auto& dest = state.registers[destination];
    for (uint32_t i = 0; i < 4u; ++i) {
        const uint32_t swizzle = (w[1] >> (i * 3u)) & 7u;
        if (swizzle < 4u) dest[i] = value[swizzle];
        else if (swizzle == 4u || swizzle == 5u) dest[i] = swizzle == 5u ? 1.0f : 0.0f;
        else if (swizzle != 7u) Reject("fetch destination swizzle", swizzle);
    }
}
