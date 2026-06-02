#include "arm_neon_2reg_narrow.h"

#include <cstdint>
#include <cstring>

#include "../core/cerf_emulator.h"
#include "arm_cpu.h"
#include "arm_vfp.h"

REGISTER_SERVICE(ArmNeon2RegNarrow);

void ArmNeon2RegNarrow::HandleNarrow(uint32_t op_sel, uint32_t esize_out,
                                     uint32_t d_idx, uint32_t m_idx) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t ebytes_out = esize_out / 8u;
    const uint32_t ebytes_in  = 2u * ebytes_out;
    const uint32_t esize_in   = 2u * esize_out;
    const uint32_t elements   = 64u / esize_out;

    /* esize_out ∈ {8, 16, 32}: 2^esize_out fits in uint64_t. */
    const uint64_t out_umax = (uint64_t{1} << esize_out) - 1u;
    const int64_t  out_smax = (int64_t{1}  << (esize_out - 1u)) - 1;
    const int64_t  out_smin = -(int64_t{1} << (esize_out - 1u));

    bool saturated = false;
    const uint8_t* src = reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx]);
    uint8_t res[8];

    for (uint32_t e = 0; e < elements; ++e) {
        const uint8_t* p = src + e * ebytes_in;
        uint64_t result_bits = 0;

        if (op_sel == kMovn) {
            /* Truncate: low esize_out bits of each 2*esize-bit input. */
            result_bits = ArmVfp::LoadIntU(p, esize_in);
        } else if (op_sel == kQmovnS) {
            int64_t v = ArmVfp::LoadIntS(p, esize_in);
            if      (v > out_smax) { v = out_smax; saturated = true; }
            else if (v < out_smin) { v = out_smin; saturated = true; }
            result_bits = static_cast<uint64_t>(v);
        } else if (op_sel == kQmovnU) {
            uint64_t v = ArmVfp::LoadIntU(p, esize_in);
            if (v > out_umax) { v = out_umax; saturated = true; }
            result_bits = v;
        } else {
            /* kQmovun: signed input, unsigned output. Negative inputs
               clamp to 0; > out_umax clamp to out_umax. */
            int64_t v = ArmVfp::LoadIntS(p, esize_in);
            if (v < 0) {
                result_bits = 0;
                saturated   = true;
            } else if (static_cast<uint64_t>(v) > out_umax) {
                result_bits = out_umax;
                saturated   = true;
            } else {
                result_bits = static_cast<uint64_t>(v);
            }
        }
        std::memcpy(res + e * ebytes_out, &result_bits, ebytes_out);
    }
    std::memcpy(&state->vfp_d[d_idx], res, 8);
    if (saturated) {
        state->fpscr |= ArmVfp::kFpscrQcMask;
    }
}

void __cdecl ArmNeon2RegNarrow::HandleNarrowHelper(ArmNeon2RegNarrow* svc,
                                                   uint32_t op_sel,
                                                   uint32_t esize_out,
                                                   uint32_t d_idx,
                                                   uint32_t m_idx) {
    svc->HandleNarrow(op_sel, esize_out, d_idx, m_idx);
}
