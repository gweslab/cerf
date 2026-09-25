#pragma once

#include "../mmc/emmc_card_base.h"

class SkHynixH26m52002ckr : public EmmcCardBase {
public:
    using EmmcCardBase::EmmcCardBase;

protected:
    SdCardCid                       Cid() const override;
    EmmcCsdFields                   Csd() const override;
    std::span<const EmmcExtCsdByte> ExtCsdProperties() const override;
    uint32_t                        SectorCount() const override;
    uint8_t                         ErasedMemCont() const override;
};
