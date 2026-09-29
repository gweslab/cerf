#include "vr41xx_piu_state_table.h"

#include "vr41xx_piu_regs.h"

namespace cerf_vr41xx_piu_detail {

uint16_t StateAfterCntWrite(uint16_t state, uint16_t old_cfg, uint16_t new_cfg, uint16_t ascn) {
    const uint16_t mode = (new_cfg >> 3) & 0x3u;

    const bool pwr0 = (old_cfg & kPiuPwr) != 0, pwr1 = (new_cfg & kPiuPwr) != 0;
    if (!pwr0 && pwr1 && state == kStDisable) state = kStStandby;
    else if (pwr0 && !pwr1)                   state = kStDisable;

    const bool seq0 = (old_cfg & kSeqEn) != 0, seq1 = (new_cfg & kSeqEn) != 0;
    if (!seq0 && seq1 && state == kStStandby) {
        /* Standby -> ADPortScan on "PIUSeqEN = 1 & ADPSStart = 1"; the scan completes and
           the state returns to the pre-scan Standby (VR4121 UM Figure 20-4 + 20.2 (3),
           VR4102 UM Figure 19-4 + 19.2). */
        if (ascn & kAdpsStart) {
            state = kStAdPortScan;
        } else {
            state = (mode == 1) ? kStCmdScan : kStWaitPenTouch;
        }
    } else if (seq0 && !seq1 && state != kStDisable) {
        state = kStStandby;
    }

    /* nec_mobilepro_700_ce2 touch.dll sub_15A04A8 flips PIUMODE from command back to
       coordinate with PIUSEQEN still set. */
    if (((old_cfg >> 3) & 0x3u) != mode && seq0 && seq1 && state != kStDisable &&
        state != kStStandby) {
        state = (mode == 1) ? kStCmdScan : kStWaitPenTouch;
    }
    return state;
}

}
