#include "../sa11xx/sa11xx_processor_config_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../../socs/sa11xx/sa1100_id.h"

namespace {

class Sa1100ProcessorConfig : public Sa11xxProcessorConfigBase {
public:
    using Sa11xxProcessorConfigBase::Sa11xxProcessorConfigBase;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Sa1100;
    }

    /* proc-sa1100.S:276  sa1100 = 0x4401a110 mask 0xfffffff0. */
    uint32_t Midr() const override { return 0x4401A110u; }
    uint32_t Ctr()  const override { return 0x4401A110u; }
};

}  /* namespace */

REGISTER_SERVICE_AS(Sa1100ProcessorConfig, ArmProcessorConfig);
