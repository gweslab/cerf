#pragma once

#include <cstdint>

#include "../core/service.h"

struct DecodedInsn;

class ArmProcessorConfig : public Service {
public:
    using Service::Service;

    virtual uint32_t PcStoreOffset()              const = 0;
    virtual bool     BaseRestoredAbortModel()     const = 0;
    virtual bool     MemoryBeforeWritebackModel() const = 0;
    virtual bool     GenerateSyscalls()           const = 0;
    virtual uint32_t CacheLineSize()              const = 0;
    virtual uint32_t Midr()                       const = 0;
    virtual uint32_t Ctr()                        const = 0;

    /* Issue cycles for one decoded ARM/Thumb instruction. Concretes
       classify by place_fn or DecodedInsn fields and return the
       value per their chip's instruction-timing reference. Used by
       the JIT to advance ArmCpuState::guest_cycle_counter inline. */
    virtual uint16_t CycleCostFor(const DecodedInsn& d) const;

    /* Guest CPU clock divided by OST clock. SA-1110 §9.4.1: OSCR =
       3.6864 MHz; SA-1110 typical core clock = 206 MHz. Other SoCs
       override per their own datasheet. Used by the OS Timer to
       translate (cycles − baseline) → OSCR ticks. */
    virtual uint32_t CpuToOscrDivider()           const { return 56; }

    /* CPU cycles per external-crystal (CKIH-like) tick. Used by
       peripherals that select an external-crystal clock source. */
    virtual uint32_t CpuToHighfreqClockDivider()  const { return 1; }

    /* CPU cycles per low-frequency-reference (CKIL-like 32 kHz) tick. */
    virtual uint32_t CpuToLowfreqClockDivider()   const { return 1; }

    virtual uint32_t CpuClockHz()                 const = 0;

    virtual bool     HasDsp()                     const = 0;
    virtual bool     HasLoadStoreDouble()         const = 0;

    virtual bool     HasClz()                     const { return false; }
    virtual bool     HasBlxReg()                  const { return false; }

    /* DO NOT override true on an ARMv4 SoC — CE kernel abort
       handlers depend on cond=NV NOP fallthrough (ARM ARM v4
       §A1.2: UNPREDICTABLE pre-ARMv5); UND-trapping cascades. */
    virtual bool     HasArmv5UnconditionalSpace() const { return false; }

    virtual bool     HasMovwMovt()                const { return false; }
    virtual bool     HasBitField()                const { return false; }
    virtual bool     HasRev()                     const { return false; }
    virtual bool     HasExtendRotate()            const { return false; }
    virtual bool     HasLdrexStrex()              const { return false; }
    virtual bool     HasBarrierInsn()             const { return false; }
    virtual bool     HasCp15V6()                  const { return false; }
    virtual bool     HasCp15V7()                  const { return false; }
    virtual bool     HasVmsav7()                  const { return false; }

    virtual uint32_t Clidr()                      const { return 0; }
    virtual uint32_t Ccsidr(uint32_t /*csselr*/)  const { return 0; }

    virtual bool     HasVfp()                     const { return false; }
    virtual bool     HasNeon()                    const { return false; }
    virtual uint32_t Fpsid()                      const { return 0; }
    virtual uint32_t Mvfr0()                      const { return 0; }
    virtual uint32_t Mvfr1()                      const { return 0; }
};
