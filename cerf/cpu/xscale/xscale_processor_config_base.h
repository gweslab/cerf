#pragma once

#include "../arm_processor_config.h"

class XscaleProcessorConfigBase : public ArmProcessorConfig {
public:
    using ArmProcessorConfig::ArmProcessorConfig;

    uint32_t PcStoreOffset() const override;
    bool BaseRestoredAbortModel() const override;
    uint32_t CacheLineSize() const override;
    bool HasDsp() const override;
    bool HasAuxControlRegister() const override;
    bool HasLoadStoreDouble() const override;
    bool HasPreload() const override;
    bool HasClz() const override;
    bool HasLoadToPcInterworking() const override;
    bool HasBlxReg() const override;
    bool HasArmv5UnconditionalSpace() const override;
};
