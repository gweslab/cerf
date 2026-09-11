#include "imx51_gpu3d_shader.h"
#include <algorithm>

/* Mesa e97ad748 src/freedreno/ir2/instr-a2xx.h: instr_cf_exec_t,
   instr_cf_jmp_call_t; disasm-a2xx.c: disasm_a2xx; ir2_assemble.c: CF address fixups. */
void Imx51Gpu3dShader::Run(std::span<const uint32_t> program, bool pixel,
                          const std::unordered_map<uint32_t, uint32_t>& regs,
                          uint32_t config, Imx51Gpu3dShaderState& state) {
    RunInvocations(program, pixel, regs, config, {&state, 1});
}

void Imx51Gpu3dShader::RunQuad(std::span<const uint32_t> program,
                              const std::unordered_map<uint32_t, uint32_t>& regs,
                              uint32_t config, std::array<Imx51Gpu3dShaderState, 4>& states) {
    RunInvocations(program, true, regs, config, states);
}

void Imx51Gpu3dShader::RunInvocations(std::span<const uint32_t> program, bool pixel,
                                     const std::unordered_map<uint32_t, uint32_t>& regs,
                                     uint32_t config, std::span<Imx51Gpu3dShaderState> states) {
    if (program.empty() || program.size() % 3u || program.size() > 1536u)
        Reject("program length", static_cast<uint32_t>(program.size()));
    auto control = [&](uint32_t pc) {
        if (uint64_t(pc) * 3u + 2u >= uint64_t(program.size()) * 2u) Reject("control address", pc);
        const size_t offset = size_t(pc / 2u) * 3u;
        return (pc & 1u) ? (uint64_t(program[offset + 1u]) >> 16) | (uint64_t(program[offset + 2u]) << 16)
                         : uint64_t(program[offset]) | (uint64_t(program[offset + 1u] & 0xFFFFu) << 32);
    };
    uint32_t limit = static_cast<uint32_t>(program.size() / 3u * 2u);
    for (uint32_t i = 0; i < limit; ++i) {
        const uint64_t cf = control(i);
        const uint32_t op = static_cast<uint32_t>(cf >> 44);
        if ((op >= 1u && op <= 6u) || op == 13u || op == 14u) {
            const uint32_t address = static_cast<uint32_t>(cf & 511u);
            const uint32_t count = static_cast<uint32_t>((cf >> 12) & 7u);
            // Empty clauses have no instruction extent, including an empty EXEC_END.
            if (!count) continue;
            if (uint64_t(address + count) * 3u > program.size()) Reject("instruction span", address);
            if (address * 2u <= i) Reject("instruction overlaps control", address);
            // CF targets count 48-bit entries; EXEC addresses count 96-bit slots.
            limit = std::min(limit, address * 2u);
        }
    }
    struct Loop { uint32_t remaining, id; int32_t step, saved_address; };
    struct Cursor {
        uint32_t pc = 0, steps = 0, address = 0, remaining = 0, sequence = 0;
        bool predicate = false, end = false, finished = false;
        float previous = 0;
        std::vector<uint32_t> return_stack;
        std::vector<Loop> loops;
    };
    std::array<Cursor, 4> cursors{};
    const bool quad = states.size() == 4;
    for (auto& state : states) {
        state.export_mask = 0;
        state.memory_exports.clear();
        state.killed = false;
        state.texture_lod = 0;
        state.texture_gradients_x = {};
        state.texture_gradients_y = {};
        state.loop_address = 0;
    }
    auto finish = [&](size_t lane) {
        cursors[lane].finished = true;
        if (states[lane].killed) {
            states[lane].export_mask = 0;
            states[lane].memory_exports.clear();
        }
    };
    // Cooperatively advance each invocation to its next FETCH. ALU executes
    // with real helper values, so nonlinear coordinate derivatives are not
    // approximated by propagating input gradients through arithmetic.
    auto advance = [&](size_t lane) {
        auto& cursor = cursors[lane];
        auto& state = states[lane];
        auto& pc = cursor.pc;
        auto& predicate = cursor.predicate;
        auto& previous = cursor.previous;
        auto& loops = cursor.loops;
        auto& return_stack = cursor.return_stack;
        while (!cursor.finished) {
            if (cursor.remaining) {
                if (cursor.sequence & 1u) return true;
                const size_t offset = size_t(cursor.address) * 3u;
                const bool was_killed = state.killed;
                Alu({program[offset], program[offset + 1u], program[offset + 2u]},
                    pixel, regs, state, predicate, previous);
                ++cursor.address;
                --cursor.remaining;
                cursor.sequence >>= 2;
                if (state.killed && !was_killed) {
                    if (!quad) finish(lane);
                    // Let the other lanes reach a kill or FETCH before deciding
                    // whether all are dead. Surviving lanes still need helpers.
                    return false;
                }
                continue;
            }
            if (cursor.end) { finish(lane); return false; }
            if (cursor.steps++ == 4096u) Reject("instruction budget", 4096u);
            if (pc >= limit) Reject("control fallthrough", pc);
            const uint64_t cf = control(pc++);
            const uint32_t op = static_cast<uint32_t>(cf >> 44);
            if (op == 12u) {
                // ALLOC reserves hardware output capacity (Mesa write_cfs/ir2_assemble).
                // Exports are preallocated and memory exports grow on demand here.
                continue;
            }
            if (op == 15u) {
                // MARK_VS_FETCH_DONE is a scheduling hint (Xenia ucode.h).
                // Fetch completes synchronously; no outstanding work needs draining.
                continue;
            }
            if (op == 0u) continue;
            if (op == 7u || op == 8u) {
                // Mesa's A2xx loop layout has no Xenos repeat/predicated-break bits.
                if (cf & 0x7FFFFE0FC00ull) Reject("loop reserved fields", static_cast<uint32_t>(cf));
                const uint32_t target = static_cast<uint32_t>(cf & 1023u);
                if (target >= limit) Reject("loop target", target);
                const uint32_t id = static_cast<uint32_t>((cf >> 16) & 31u);
                if (op == 8u) {
                    if (loops.empty() || loops.back().id != id) Reject("unmatched loop end", id);
                    auto& loop = loops.back();
                    if (--loop.remaining) {
                        state.loop_address += loop.step;
                        pc = target;
                    } else {
                        state.loop_address = loop.saved_address;
                        loops.pop_back();
                    }
                    continue;
                }
                // NXP SQ_CF_LOOP: 8-bit count/start/step; signed step follows Xenia's model.
                const uint32_t value = Register(regs, 0x4908u + id);
                const uint32_t count = value & 255u;
                if (!count) { pc = target; continue; }
                if (loops.size() == 64u) Reject("loop stack budget", 64u);
                const uint32_t step = (value >> 16) & 255u;
                loops.push_back({count, id, step < 128u ? int32_t(step) : int32_t(step) - 256, state.loop_address});
                state.loop_address = static_cast<int32_t>((value >> 8) & 255u);
                continue;
            }
            if (op == 10u) {
                // Xenia sequencer model: an empty RETURN falls through.
                if (!return_stack.empty()) {
                    pc = return_stack.back();
                    return_stack.pop_back();
                }
                continue;
            }
            auto boolean = [&] {
                const uint32_t index = static_cast<uint32_t>((cf >> 34) & 255u);
                return ((Register(regs, 0x4900u + index / 32u) >> (index % 32u)) & 1u) != 0;
            };
            const bool condition = ((cf >> 42) & 1u) != 0;
            if (op == 9u || op == 11u) {
                // Mesa emits mode zero with a CF-entry target and a direction hint.
                // The alternate address mode has no established A2xx execution rule.
                if ((cf >> 43) & 1u) Reject("jump address mode", 1u);
                const bool force = ((cf >> 13) & 1u) != 0;
                const bool test = force ? condition : ((cf >> 14) & 1u) ? predicate : boolean();
                if (force || test == condition) {
                    const uint32_t target = static_cast<uint32_t>(cf & 1023u);
                    if (target >= limit) Reject("jump target", target);
                    const bool forward = ((cf >> 33) & 1u) != 0;
                    if (op == 11u && forward != (target > pc - 1u)) Reject("jump direction", target);
                    if (op == 9u) {
                        // Emulator safety bound, not a claim about hardware stack depth.
                        if (return_stack.size() == 64u) Reject("call stack budget", 64u);
                        return_stack.push_back(pc);
                    }
                    pc = target;
                }
                continue;
            }
            if (!((op >= 1u && op <= 6u) || op == 13u || op == 14u)) Reject("control opcode", op);
            // CLEAN avoids a hardware predicate stall; clauses execute synchronously here.
            // Xenia ucode.h models CLEAN as boolean-conditioned, without clearing P.
            bool execute = true;
            if (op == 3u || op == 4u || op == 13u || op == 14u) execute = boolean() == condition;
            if (op == 5u || op == 6u) execute = predicate == condition;
            if (execute) {
                cursor.address = static_cast<uint32_t>(cf & 511u);
                cursor.remaining = static_cast<uint32_t>((cf >> 12) & 7u);
                cursor.sequence = static_cast<uint32_t>((cf >> 16) & 4095u);
            }
            // Save clause-entry eligibility: ALU may change the predicate later.
            cursor.end = op == 2u || ((op == 4u || op == 6u || op == 14u) && execute);
            }
        return false;
    };
    for (;;) {
        std::array<bool, 4> ready{};
        bool pending_kill = false;
        for (size_t lane = 0; lane < states.size(); ++lane) {
            ready[lane] = advance(lane);
            pending_kill |= !ready[lane] && !cursors[lane].finished;
        }
        bool live = false;
        for (size_t lane = 0; lane < states.size(); ++lane)
            live |= !cursors[lane].finished && !states[lane].killed;
        if (!live) {
            for (size_t lane = 0; lane < states.size(); ++lane) finish(lane);
            return;
        }
        if (pending_kill) continue;
        if (std::none_of(ready.begin(), ready.end(), [](bool value) { return value; })) return;
        bool aligned = quad;
        for (size_t lane = 0; lane < states.size(); ++lane)
            aligned &= ready[lane] && cursors[lane].address == cursors[0].address;
        // Snapshot all source values before any FETCH can overwrite a register.
        for (size_t lane = 0; quad && lane < states.size(); ++lane) if (ready[lane]) {
            const uint32_t word = program[size_t(cursors[lane].address) * 3u];
            const uint32_t source = (word >> 5) & 63u;
            states[lane].gradient_mask &= ~(uint64_t{1} << source);
            if (aligned) {
                for (unsigned component = 0; component < 4u; ++component) {
                    states[lane].gradients_x[source][component] = states[lane | 1u].registers[source][component]
                        - states[lane & ~size_t{1}].registers[source][component];
                    states[lane].gradients_y[source][component] = states[lane | 2u].registers[source][component]
                        - states[lane & ~size_t{2}].registers[source][component];
                }
                states[lane].gradient_mask |= uint64_t{1} << source;
            }
            // Divergent fetch sites retain unavailable gradients. Explicit-LOD
            // samples remain usable; implicit derivatives there are undefined
            // by GLSL ES 1.00 Appendix A, section 6.
        }
        for (size_t lane = 0; lane < states.size(); ++lane) if (ready[lane]) {
            auto& cursor = cursors[lane];
            const size_t offset = size_t(cursor.address) * 3u;
            Fetch({program[offset], program[offset + 1u], program[offset + 2u]},
                  regs, config, states[lane], cursor.predicate);
            ++cursor.address;
            --cursor.remaining;
            cursor.sequence >>= 2;
        }
    }
}
/* Mesa e97ad748 instr-a2xx.h: instr_alu_t; disasm-a2xx.c: print_srcreg;
   ir2_assemble.c: alu_swizzle_scalar, alu_swizzle_scalar2, src_reg_byte;
   ir2_nir.c: emit_alu, store_output, extra_position_exports;
   ir2_assemble.c: relative_addr on export32; fd2_gmem.c: binning export constants. */
