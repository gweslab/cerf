#include "arm_neon_vext.h"

#include <cstdint>
#include <cstring>

#include "../core/cerf_emulator.h"
#include "arm_cpu.h"

REGISTER_SERVICE(ArmNeonVext);

void ArmNeonVext::HandleVext(uint32_t d_idx, uint32_t n_idx, uint32_t m_idx,
                             uint32_t imm4_bytes, uint32_t q) {
    auto* state = emu_.Get<ArmCpu>().State();

    if (q == 0u) {
        /* Doubleword: concat (D[m]:D[n]) into 16-byte buffer, copy 8
           consecutive bytes starting at offset imm4_bytes into D[d]. */
        uint8_t buf[16];
        std::memcpy(buf,        &state->vfp_d[n_idx], 8);
        std::memcpy(buf + 8u,   &state->vfp_d[m_idx], 8);
        uint8_t res[8];
        std::memcpy(res, buf + imm4_bytes, 8);
        std::memcpy(&state->vfp_d[d_idx], res, 8);
    } else {
        /* Quadword: concat (Q[m]:Q[n]) — i.e. (D[m+1]:D[m]:D[n+1]:D[n])
           little-endian — into 32-byte buffer, copy 16 consecutive
           bytes starting at offset imm4_bytes into Q[d]. */
        uint8_t buf[32];
        std::memcpy(buf,        &state->vfp_d[n_idx    ], 8);
        std::memcpy(buf +  8u,  &state->vfp_d[n_idx + 1], 8);
        std::memcpy(buf + 16u,  &state->vfp_d[m_idx    ], 8);
        std::memcpy(buf + 24u,  &state->vfp_d[m_idx + 1], 8);
        uint8_t res[16];
        std::memcpy(res, buf + imm4_bytes, 16);
        std::memcpy(&state->vfp_d[d_idx    ], res,       8);
        std::memcpy(&state->vfp_d[d_idx + 1], res + 8u,  8);
    }
}

void __cdecl ArmNeonVext::HandleVextHelper(ArmNeonVext* svc, uint32_t d_idx,
                                           uint32_t n_idx, uint32_t m_idx,
                                           uint32_t imm4_bytes, uint32_t q) {
    svc->HandleVext(d_idx, n_idx, m_idx, imm4_bytes, q);
}
