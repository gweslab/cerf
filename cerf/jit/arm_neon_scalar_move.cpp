#include "arm_neon_scalar_move.h"

#include <cstdint>
#include <cstring>

#include "../core/cerf_emulator.h"
#include "arm_cpu.h"

REGISTER_SERVICE(ArmNeonScalarMove);

void ArmNeonScalarMove::HandleCoreToScalar(uint32_t d_idx, uint32_t lane_index,
                                           uint32_t esize, uint32_t rt_index) {
    auto* state = emu_.Get<ArmCpu>().State();
    uint8_t* d_bytes = reinterpret_cast<uint8_t*>(&state->vfp_d[d_idx]);
    const uint32_t rt_val = state->gprs[rt_index];

    if (esize == 8u) {
        d_bytes[lane_index] = static_cast<uint8_t>(rt_val & 0xFFu);
    } else {
        /* esize == 16. */
        const uint16_t halfword = static_cast<uint16_t>(rt_val & 0xFFFFu);
        std::memcpy(d_bytes + lane_index * 2u, &halfword, 2);
    }
}

void ArmNeonScalarMove::HandleScalarToCore(uint32_t n_idx, uint32_t lane_index,
                                           uint32_t esize,
                                           uint32_t unsigned_ext,
                                           uint32_t rt_index) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint8_t* n_bytes =
        reinterpret_cast<const uint8_t*>(&state->vfp_d[n_idx]);

    uint32_t result;
    if (esize == 8u) {
        const uint8_t byte = n_bytes[lane_index];
        if (unsigned_ext) {
            result = byte;
        } else {
            result = static_cast<uint32_t>(static_cast<int32_t>(
                static_cast<int8_t>(byte)));
        }
    } else {
        /* esize == 16. */
        uint16_t halfword;
        std::memcpy(&halfword, n_bytes + lane_index * 2u, 2);
        if (unsigned_ext) {
            result = halfword;
        } else {
            result = static_cast<uint32_t>(static_cast<int32_t>(
                static_cast<int16_t>(halfword)));
        }
    }

    state->gprs[rt_index] = result;
}

void __cdecl ArmNeonScalarMove::HandleCoreToScalarHelper(
        ArmNeonScalarMove* svc, uint32_t d_idx, uint32_t lane_index,
        uint32_t esize, uint32_t rt_index) {
    svc->HandleCoreToScalar(d_idx, lane_index, esize, rt_index);
}

void __cdecl ArmNeonScalarMove::HandleScalarToCoreHelper(
        ArmNeonScalarMove* svc, uint32_t n_idx, uint32_t lane_index,
        uint32_t esize, uint32_t unsigned_ext, uint32_t rt_index) {
    svc->HandleScalarToCore(n_idx, lane_index, esize, unsigned_ext, rt_index);
}
