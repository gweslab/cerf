#pragma once

#include "../../core/service.h"

#include <cstddef>
#include <cstdint>

class StateWriter;
class StateReader;

/* iso15765R.dll diagnostic TP responder (Cid 33 = BusId 2, Cid 34 = BusId 1; RX
   router sub_C090A024). Answers TP_OPEN/GET_CFG/CLOSE so VNIDiagSvc's connect()
   (sub_C0908628) completes; FordSync2VmcuPeer owns the UART2 transport + dispatch. */
class FordSync2VmcuDiagChannel : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;

    static constexpr uint8_t kCid1 = 33u;  /* BusId 2 */
    static constexpr uint8_t kCid2 = 34u;  /* BusId 1 */

    /* A reliable-data frame the head sent on a diagnostic Cid; msg[0] = TP type. */
    void HandleInbound(uint8_t cid, const uint8_t* msg, std::size_t n);
    void OnLinkReset();

    /* Forwarded from FordSync2VmcuPeer's Save/Restore (this is a plain Service,
       not auto-enumerated for hibernation). */
    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);

private:
    uint8_t tx_seq_[2] = {0u, 0u};  /* per-Cid (33, 34) reliable-data TX seq */
    uint8_t handle_ = 0u;           /* monotonic nonzero TP_OPEN handle assigner */
};
