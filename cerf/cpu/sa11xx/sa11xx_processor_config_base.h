#pragma once

#include "../arm_processor_config.h"

struct DecodedInsn;

/* Common StrongARM SA-11x0 ARMv4 config (proc-sa1100.S:13: SA-1100 and
   SA-1110 share everything but CPU ID). Concretes supply Midr/Ctr + gate. */
class Sa11xxProcessorConfigBase : public ArmProcessorConfig {
public:
    using ArmProcessorConfig::ArmProcessorConfig;

    /* ARM DDI 0100I "Reading the program counter" (p. A2-9): STR/STM of R15
       stores insn+8 or insn+12 - "IMPLEMENTATION DEFINED". The SA-1110
       Developer's Manual and the SA-110 datasheet's "ARM Implementation
       Options" chapter do not document the choice; 8 is unverified. */
    uint32_t PcStoreOffset()              const override { return 8; }

    /* proc-sa1100.S:238  dabort=v4_early_abort → base-RESTORED. */
    bool     BaseRestoredAbortModel()     const override { return true; }

    /* proc-sa1100.S:33  #define DCACHELINESIZE 32. */
    uint32_t CacheLineSize()              const override { return 32; }

    /* proc-sa1100.S:242 cpu_arch_name "armv4" - StrongARM has no Thumb. */
    bool     HasThumb()                   const override { return false; }
    bool     HasDsp()                     const override { return false; }
    bool     HasLoadStoreDouble()         const override { return false; }

    uint16_t CycleCostFor(const DecodedInsn& d) const override;

    /* SA-1110 Dev Manual §8.2: nRESET clears CCF, selecting the lowest core
       clock, which Table 8-1 gives as 16 x the 3.6864-MHz crystal. */
    uint32_t CpuClockHz() const override { return 16u * 3686400u; }
};
