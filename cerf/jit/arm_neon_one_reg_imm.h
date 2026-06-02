#pragma once

#include <cstdint>

#include "../core/service.h"

/* One register and a modified immediate value (A7.4.6):
   VMOV / VMVN / VBIC / VORR (immediate). */
class ArmNeonOneRegImm : public Service {
public:
    using Service::Service;

    /* Operation selector — the place_fn determines this from the
       (op, cmode) bits per A8.8.339/353/288/359. */
    static constexpr uint32_t kOpVmov = 0u;  /* D[d] = imm64        */
    static constexpr uint32_t kOpVmvn = 1u;  /* D[d] = ~imm64       */
    static constexpr uint32_t kOpVbic = 2u;  /* D[d] = D[d] & ~imm64 */
    static constexpr uint32_t kOpVorr = 3u;  /* D[d] = D[d] | imm64 */

    void HandleOneRegImm(uint32_t op_type, uint32_t d_idx,
                         uint64_t imm64, uint32_t regs);

    /* Helper takes imm64 as two 32-bit halves because x86 __cdecl pushes
       32-bit args; the trampoline reassembles them. */
    static void __cdecl HandleOneRegImmHelper(ArmNeonOneRegImm* svc,
                                              uint32_t op_type, uint32_t d_idx,
                                              uint32_t imm64_lo, uint32_t imm64_hi,
                                              uint32_t regs);
};
