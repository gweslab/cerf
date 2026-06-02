#include "arm_neon_2reg_bitcount.h"

#include <cstdint>
#include <cstring>

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "arm_cpu.h"

REGISTER_SERVICE(ArmNeon2RegBitcount);

void ArmNeon2RegBitcount::HandleBitcount(uint32_t op, uint32_t d_idx,
                                         uint32_t m_idx, uint32_t esize,
                                         uint32_t regs) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t ebytes   = esize / 8u;
    const uint32_t elements = 8u / ebytes;

    for (uint32_t r = 0; r < regs; ++r) {
        const uint8_t* src = reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx + r]);
        uint8_t res[8];
        for (uint32_t e = 0; e < elements; ++e) {
            uint64_t val = 0;
            std::memcpy(&val, src + e * ebytes, ebytes);
            uint32_t result = 0;
            switch (op) {
                case kCls: {
                    /* A8.8.299: count consecutive bits below MSB matching
                       the sign bit. Range [0, esize-1]. */
                    const uint32_t sign = static_cast<uint32_t>((val >> (esize - 1u)) & 1u);
                    for (int32_t i = static_cast<int32_t>(esize) - 2; i >= 0; --i) {
                        const uint32_t bit = static_cast<uint32_t>((val >> i) & 1u);
                        if (bit != sign) break;
                        ++result;
                    }
                    break;
                }
                case kClz: {
                    /* A8.8.302: count leading zeros from MSB. Range [0, esize]. */
                    for (int32_t i = static_cast<int32_t>(esize) - 1; i >= 0; --i) {
                        if ((val >> i) & 1u) break;
                        ++result;
                    }
                    break;
                }
                case kCnt: {
                    /* A8.8.304: popcount of low 8 bits (place_fn enforces esize=8). */
                    uint64_t v = val & 0xFFull;
                    while (v != 0u) {
                        result += static_cast<uint32_t>(v & 1u);
                        v >>= 1;
                    }
                    break;
                }
                default:
                    LOG(Caution, "HandleBitcount: unhandled op=%u\n", op);
                    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            const uint64_t result_raw = static_cast<uint64_t>(result);
            std::memcpy(res + e * ebytes, &result_raw, ebytes);
        }
        std::memcpy(&state->vfp_d[d_idx + r], res, 8);
    }
}

void __cdecl ArmNeon2RegBitcount::HandleBitcountHelper(ArmNeon2RegBitcount* svc,
                                                       uint32_t op,
                                                       uint32_t d_idx, uint32_t m_idx,
                                                       uint32_t esize, uint32_t regs) {
    svc->HandleBitcount(op, d_idx, m_idx, esize, regs);
}
