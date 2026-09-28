#include "sa11xx_processor_config_base.h"

#include <intrin.h>

#include "../../jit/arm/decoded_insn.h"
#include "../../jit/arm/place_fns.h"

/* SA-1110 Dev Man §4.2 Table 4-1 issue cycles; the control field is mask<0>
   (DDI 0406C A8.8.112). */
uint16_t Sa11xxProcessorConfigBase::CycleCostFor(const DecodedInsn& d) const {
    uint16_t cost = 1;
    if (d.place_fn == &PlaceBlockDataTransfer) {
        const unsigned n = __popcnt16(d.register_list);
        cost = static_cast<uint16_t>(n < 2 ? 2 : n);
    } else if (d.place_fn == &PlaceMRSorMSR) {
        cost = (d.s != 0u && (d.crn & 0x1u) != 0u) ? 3 : 1;
    } else if (d.place_fn == &PlaceMSRImmediate) {
        cost = (d.crn & 0x1u) != 0u ? 3 : 1;
    } else if (d.place_fn == &PlaceMultiply) {
        cost = d.op1 >= 4u ? 2 : 1;
    } else if (d.place_fn == &PlaceLoadStoreExtension) {
        cost = d.op1 == 0u ? 2 : 1;
    }
    return cost;
}
