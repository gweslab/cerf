#include "ford_sync2_vmcu_diag_channel.h"

#include "ford_sync2_vmcu_peer.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../board_context.h"
#include "ford_sync_2_id.h"
#include "../../state/state_stream.h"

#include <cstdint>

bool FordSync2VmcuDiagChannel::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::FordSync2;
}

void FordSync2VmcuDiagChannel::HandleInbound(uint8_t cid, const uint8_t* msg,
                                             std::size_t n) {
    if (n < 4u) return;  /* every TP request is [type][b1][TID:2] or longer */
    auto& peer = emu_.Get<FordSync2VmcuPeer>();
    const std::size_t idx = static_cast<std::size_t>(cid - kCid1);
    switch (msg[0]) {
        case 0x01u: {  /* TP_OPEN -> 129 TP_OPEN_COMPLETE (sub_C0905DE4): HANDLE must be
                          nonzero + distinct per open (0 rejected; router drops a dup). */
            handle_ = static_cast<uint8_t>((handle_ % 255u) + 1u);
            const uint8_t reply[5] = {129u, handle_, msg[2], msg[3], 0x00u};
            peer.InjectReliable(cid, tx_seq_[idx], reply, sizeof(reply));
            break;
        }
        case 0x02u: {  /* TP_CLOSE -> 130 CLOSE_COMPLETE (RX router case 130, ISO_Close
                          sub_C09055A8 waits on it): resolved by HANDLE = msg[1]. */
            const uint8_t reply[5] = {130u, msg[1], msg[2], msg[3], 0x00u};
            peer.InjectReliable(cid, tx_seq_[idx], reply, sizeof(reply));
            break;
        }
        case 0x03u: {  /* TP_GET_CFG -> 131 GET_CFG_COMPLETE (sub_C0905EF8). The 62 config
                          bytes are inert: iso15765R reads them back only via TpIoctlGetOption
                          (sub_C09066D0) verbatim with no validation, never from the live
                          ISO-TP addressing (the guest-set lower-driver config). */
            uint8_t reply[67] = {0u};
            reply[0] = 131u;
            reply[1] = msg[1];  /* echo the HANDLE the guest assigned */
            reply[2] = msg[2];
            reply[3] = msg[3];
            reply[4] = 0x00u;   /* StatusCode */
            peer.InjectReliable(cid, tx_seq_[idx], reply, sizeof(reply));
            break;
        }
        case 0x05u: {  /* TP_SEND -> 133 SEND_CPL Status 0: the send (sub_C0908B7C) leaves the
                          handle state ctx+0x44 at 5; the RX router sub_C090A024 accepts 133
                          SEND_CPL ungated but 134 SEND_CFM only at state 7, and sub_C0907D60's
                          Status-0 path signals the send's completion event. */
            const uint8_t reply[5] = {133u, msg[1], msg[2], msg[3], 0x00u};
            peer.InjectReliable(cid, tx_seq_[idx], reply, sizeof(reply));
            break;
        }
        default:
            LOG(Caution,
                "[VMCU] unmodelled inbound ISO15765 diag cid=%u type=0x%02X len=%zu\n",
                static_cast<unsigned>(cid), static_cast<unsigned>(msg[0]), n);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    tx_seq_[idx] = static_cast<uint8_t>((tx_seq_[idx] + 1u) & 0x7Fu);
}

void FordSync2VmcuDiagChannel::SaveState(StateWriter& w) {
    w.Write("tx_seq", tx_seq_[0]);
    w.Write("tx_seq", tx_seq_[1]);
    w.Write("handle", handle_);
}

void FordSync2VmcuDiagChannel::RestoreState(StateReader& r) {
    r.Read("tx_seq", tx_seq_[0]);
    r.Read("tx_seq", tx_seq_[1]);
    r.Read("handle", handle_);
}

REGISTER_SERVICE(FordSync2VmcuDiagChannel);
