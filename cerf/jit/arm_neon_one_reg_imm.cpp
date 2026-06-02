#include "arm_neon_one_reg_imm.h"

#include <cstdint>

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "arm_cpu.h"

REGISTER_SERVICE(ArmNeonOneRegImm);

void ArmNeonOneRegImm::HandleOneRegImm(uint32_t op_type, uint32_t d_idx,
                                       uint64_t imm64, uint32_t regs) {
    auto* state = emu_.Get<ArmCpu>().State();
    for (uint32_t r = 0; r < regs; ++r) {
        uint64_t& d = state->vfp_d[d_idx + r];
        switch (op_type) {
            case kOpVmov: d = imm64;       break;
            case kOpVmvn: d = ~imm64;      break;
            case kOpVbic: d = d & ~imm64;  break;
            case kOpVorr: d = d | imm64;   break;
            default:
                LOG(Caution, "HandleOneRegImm: unhandled op_type=%u\n", op_type);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
    }
}

void __cdecl ArmNeonOneRegImm::HandleOneRegImmHelper(ArmNeonOneRegImm* svc,
                                                     uint32_t op_type, uint32_t d_idx,
                                                     uint32_t imm64_lo, uint32_t imm64_hi,
                                                     uint32_t regs) {
    const uint64_t imm64 =
        (static_cast<uint64_t>(imm64_hi) << 32) | static_cast<uint64_t>(imm64_lo);
    svc->HandleOneRegImm(op_type, d_idx, imm64, regs);
}
