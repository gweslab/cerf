#pragma once

#include "arm_processor_config.h"

class Armv7aProcessorConfigBase : public ArmProcessorConfig {
public:
    using ArmProcessorConfig::ArmProcessorConfig;

    /* ARM DDI 0406C.c PCStoreValue() (p. A2-47): the +12 alternative is
       permitted only before ARMv7. */
    uint32_t PcStoreOffset()              const override { return 8; }
    bool     BaseRestoredAbortModel()     const override { return true; }

    bool     HasDsp()                     const override { return true; }
    bool     HasLoadStoreDouble()         const override { return true; }
    bool     HasPreload()                 const override { return true; }
    bool     HasClz()                     const override { return true; }
    bool     HasBlxReg()                  const override { return true; }
    bool     HasThumb2()                  const override { return true; }
    bool     HasArmv5UnconditionalSpace() const override { return true; }

    /* v5T+ load-to-PC and v7 data-proc-to-PC interworking (DDI0406C §A2.3.1). */
    bool     HasLoadToPcInterworking()     const override { return true; }
    bool     HasDataProcToPcInterworking() const override { return true; }

    bool     HasMls()                     const override { return true; }
    bool     HasMovwMovt()                const override { return true; }
    bool     HasBitField()                const override { return true; }
    bool     HasRev()                     const override { return true; }
    bool     HasExtendRotate()            const override { return true; }
    bool     HasLdrexStrex()              const override { return true; }
    bool     HasBarrierInsn()             const override { return true; }
    bool     HasCp15V6()                  const override { return true; }
    bool     HasCp15V7()                  const override { return true; }
    bool     HasVmsav7()                  const override { return true; }
    /* ARM Architecture Reference Manual ARMv7-A and ARMv7-R edition
       DDI 0406C, section B3.5.1. */
    ArmSupersectionFormat SupersectionFormat() const override { return ArmSupersectionFormat::kArmV7; }
};
