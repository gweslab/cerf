#pragma once

#include <cstdint>

#include "../core/service.h"

struct DecodedInsn;

/* ARM DDI 0406C.c B3.5: whether a VMSAv7 implementation supports Supersections
   is IMPLEMENTATION DEFINED, and the extended base address in descriptor
   bits[8:5, 23:20] is a further option on top. */
enum class ArmSupersectionFormat : uint8_t {
    kUnknown,
    kNone,
    kPa32,
    kPa36,
};

class ArmProcessorConfig : public Service {
public:
    using Service::Service;

    virtual uint32_t PcStoreOffset()              const = 0;
    virtual bool     BaseRestoredAbortModel()     const = 0;
    virtual uint32_t CacheLineSize()              const = 0;
    virtual uint32_t Midr()                       const = 0;
    virtual uint32_t Ctr()                        const = 0;

    /* Issue cycles for one decoded ARM/Thumb instruction. Concretes
       classify by place_fn or DecodedInsn fields and return the
       value per their chip's instruction-timing reference. Used by
       the JIT to advance ArmCpuState::guest_cycle_counter inline. */
    virtual uint16_t CycleCostFor(const DecodedInsn& d) const;

    /* SA-1110 Dev Man §8.2 Table 8-1: CCF 01011 = 56 x the 3.6864-MHz
       crystal; §9.4.1: the OSCR increments on that crystal's rising edges. */
    virtual uint32_t CpuToOscrDivider()           const { return 56; }

    virtual uint32_t CpuToHighfreqClockDivider()  const { return 1; }
    virtual uint32_t CpuToLowfreqClockDivider()   const { return 1; }

    virtual uint32_t CpuClockHz()                 const = 0;

    virtual bool     HasDsp()                     const = 0;
    virtual bool     HasLoadStoreDouble()         const = 0;

    /* DDI 0406C.c A1.3, p. A1-30: ARMv5TE "Adds Preload Data (PLD),
       Load Register Dual (LDRD), Store Register Dual (STRD)". */
    virtual bool     HasPreload()                 const { return false; }

    /* Thumb ISA presence (v4T+). On a no-Thumb core CPSR.T is
       unwritable and BX is undefined - guests rely on that:
       jlime's linexec writes CPSR|0xEF (T set) on SA-1110 and
       expects the T write ignored, as on real silicon. */
    virtual bool     HasThumb()                   const { return true; }

    /* DDI 0406C.c p. A1-29: "ARMv6T2 introduced Thumb-2 technology. This
       technology extends the original Thumb instruction set with many 32-bit
       instructions." A6.1, p. A6-220: a halfword whose bits[15:11] are 0b11101,
       0b11110 or 0b11111 is the first halfword of a 32-bit instruction. */
    virtual bool     HasThumb2()                  const { return false; }

    /* DDI0406C §A2.3.1: LDR/POP/LDM with Rt==PC interwork (bit 0
       selects the ISA state) from ARMv5T on; on v4T they branch
       remaining in the current ISA state. */
    virtual bool     HasLoadToPcInterworking()    const { return false; }

    /* DDI0406C §A2.3.1: ARM-state data-processing with Rd==PC and
       no flag-setting interworks only from ARMv7 on; earlier
       versions branch remaining in the current ISA state. */
    virtual bool     HasDataProcToPcInterworking() const { return false; }

    virtual bool     HasClz()                     const { return false; }
    virtual bool     HasBlxReg()                  const { return false; }

    /* ARM DDI 0100I A3.2.1 (p. A3-4): "In ARMv4, any instruction with a
       condition field of 0b1111 is UNPREDICTABLE." ARM DDI 0406C.c A5.7
       (p. A5-216): "All encodings in this space are UNPREDICTABLE in
       ARMv4 and ARMv4T." */
    virtual bool     HasArmv5UnconditionalSpace() const { return false; }

    virtual bool     HasMls()                     const { return false; }
    virtual bool     HasMovwMovt()                const { return false; }
    virtual bool     HasBitField()                const { return false; }
    virtual bool     HasRev()                     const { return false; }
    virtual bool     HasExtendRotate()            const { return false; }
    virtual bool     HasLdrexStrex()              const { return false; }
    virtual bool     HasLdrexStrexV6k()           const { return false; }
    virtual bool     HasBarrierInsn()             const { return false; }

    /* DDI 0406C.c A4.4.8, p. A4-172: SDIV and UDIV are OPTIONAL in an ARMv7-A
       implementation without the Virtualization Extensions, and
       ID_ISAR0.Divide_instrs indicates the level of support. */
    virtual bool     HasIntegerDivide()           const { return false; }

    /* ARM DDI 0344K Table 3-3, p. 3-17: Cortex-A8 allocates the L1 system
       array debug operations at c15, write-only and Secure state only. */
    virtual bool     HasL1SystemArrayDebug()      const { return false; }

    virtual bool     HasCp15V6()                  const { return false; }
    virtual bool     HasCp15V7()                  const { return false; }
    virtual bool     HasVmsav7()                  const { return false; }
    virtual ArmSupersectionFormat SupersectionFormat() const { return ArmSupersectionFormat::kNone; }
    virtual bool     HasSecurityExtensions()      const { return false; }

    /* c9,c0,2 op1=1 L2 Cache Auxiliary Control Register present (Cortex-A8). */
    virtual bool     HasL2CacheAuxControl()       const { return false; }

    /* c1,c0,1 ACTLR present. ARM920T allocates no c1 op2=1 register
       (S3C2410A UM Table 2-2, p. 2-4). */
    virtual bool     HasAuxControlRegister()      const { return false; }

    virtual uint32_t Clidr()                      const { return 0; }
    virtual uint32_t Ccsidr(uint32_t /*csselr*/)  const { return 0; }

    virtual bool     HasVfp()                     const { return false; }
    virtual bool     HasNeon()                    const { return false; }
    virtual uint32_t Fpsid()                      const { return 0; }
    virtual uint32_t Mvfr0()                      const { return 0; }
    virtual uint32_t Mvfr1()                      const { return 0; }
};
