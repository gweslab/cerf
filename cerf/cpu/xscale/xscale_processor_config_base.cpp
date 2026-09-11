#include "xscale_processor_config_base.h"

/* ARM DDI 0100I "Reading the program counter" (p. A2-9);
   siemens_mp377_v1040 nk.exe sub_8040AE1C. */
uint32_t XscaleProcessorConfigBase::PcStoreOffset() const { return 8u; }

/* XScale Core Dev Manual section 2.2.5. */
bool XscaleProcessorConfigBase::BaseRestoredAbortModel() const { return true; }

/* XScale Core Dev Manual Table 7-5. */
uint32_t XscaleProcessorConfigBase::CacheLineSize() const { return 32u; }

/* XScale Core Dev Manual section 2.2.4. */
bool XscaleProcessorConfigBase::HasDsp() const { return true; }

/* XScale Core Dev Manual Table 7-3. */
bool XscaleProcessorConfigBase::HasAuxControlRegister() const { return true; }

/* XScale Core Dev Manual section 2.2.4. */
bool XscaleProcessorConfigBase::HasLoadStoreDouble() const { return true; }

/* XScale Core Dev Manual section 2.2.4. */
bool XscaleProcessorConfigBase::HasPreload() const { return true; }

/* XScale Core Dev Manual section 2.1. */
bool XscaleProcessorConfigBase::HasClz() const { return true; }

/* ARM DDI 0406C section A2.3.1. */
bool XscaleProcessorConfigBase::HasLoadToPcInterworking() const { return true; }

/* XScale Core Dev Manual section 2.1. */
bool XscaleProcessorConfigBase::HasBlxReg() const { return true; }

/* XScale Core Dev Manual section 2.1. */
bool XscaleProcessorConfigBase::HasArmv5UnconditionalSpace() const { return true; }
