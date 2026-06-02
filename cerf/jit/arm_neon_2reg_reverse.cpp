#include "arm_neon_2reg_reverse.h"

#include <cstdint>
#include <cstring>

#include "../core/cerf_emulator.h"
#include "arm_cpu.h"

REGISTER_SERVICE(ArmNeon2RegReverse);

void ArmNeon2RegReverse::HandleRev(uint32_t op, uint32_t d_idx, uint32_t m_idx,
                                   uint32_t esize, uint32_t groupsize,
                                   uint32_t regs) {
    (void)op;
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t ebytes   = esize / 8u;
    const uint32_t elements = 8u / ebytes;
    const uint32_t mask     = groupsize - 1u;

    for (uint32_t r = 0; r < regs; ++r) {
        const uint8_t* src = reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx + r]);
        uint8_t res[8];
        for (uint32_t e = 0; e < elements; ++e) {
            const uint32_t src_e = e ^ mask;
            std::memcpy(res + e * ebytes, src + src_e * ebytes, ebytes);
        }
        std::memcpy(&state->vfp_d[d_idx + r], res, 8);
    }
}

void __cdecl ArmNeon2RegReverse::HandleRevHelper(ArmNeon2RegReverse* svc, uint32_t op,
                                                 uint32_t d_idx, uint32_t m_idx,
                                                 uint32_t esize, uint32_t groupsize,
                                                 uint32_t regs) {
    svc->HandleRev(op, d_idx, m_idx, esize, groupsize, regs);
}
