#if !CERF_DEV_MODE
#define NOMINMAX
#include <windows.h>
#endif

#include "ford_sync2_vmcu_peer.h"

#include "ford_sync2_ilp_channel.h"
#include "ford_sync2_vmcu_diag_channel.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "ford_sync_2_id.h"
#include "../../socs/imx51/imx51_uart2.h"
#include "../../state/state_stream.h"

#include <cstdio>
#include <vector>

namespace {

using cerf::le::Append16;
using cerf::le::Append32;
using cerf::le::Put16;
using cerf::le::Put32;
using cerf::le::U16;
using cerf::le::U32;

uint16_t IpcmpChecksum(const uint8_t* p, std::size_t len) {
    uint32_t sum = 0u;
    for (std::size_t i = 0; i < len; ++i) sum += p[i];
    return static_cast<uint16_t>(sum);
}

}

bool FordSync2VmcuPeer::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::FordSync2;
}

void FordSync2VmcuPeer::OnReady() {
    uart_ = &emu_.Get<Imx51Uart2>();
    uart_->AttachEndpoint(this);
}

std::vector<uint8_t> FordSync2VmcuPeer::EncodeFrame(const uint8_t* payload,
                                                    std::size_t len) {
    /* sync_2 EA5T-14D544-BA.sec, IPCMP.dll sub_C0E23130. */
    std::vector<uint8_t> flat(payload, payload + len);
    Append16(flat, IpcmpChecksum(payload, len));
    flat.push_back(0u);

    std::vector<uint8_t> out;
    out.push_back(kFlag);
    std::size_t cur = 0;
    const std::size_t kN = flat.size();
    int lit = 0, tz = 0;
    while (cur < kN || lit > 0) {
        if (lit > 0) {
            out.push_back(flat[cur++]);
            if (--lit == 0 && tz > 0) { cur += static_cast<std::size_t>(tz); tz = 0; }
            continue;
        }
        if (cur >= kN) break;
        int nz = 0, z = 0;
        for (std::size_t i = cur; i < kN; ++i) {
            if (flat[i] != 0u) { if (z) break; if (++nz >= 207) break; }
            else ++z;
        }
        if (nz == 0) {
            /* sync_2 EA5T-14D544-BA.sec, IPCMP.dll sub_C0E229B0. */
            for (int rem = z; rem > 0;) {
                const int take = rem >= 15 ? 15 : rem;
                out.push_back(take == 1 ? 0x01u
                              : take == 2 ? 0xE0u
                              : static_cast<uint8_t>(0xD0u + take));
                rem -= take;
            }
            cur += static_cast<std::size_t>(z);
        } else if (nz < 0x1F && z > 1) {
            out.push_back(static_cast<uint8_t>(nz + 0xE0));
            tz = 2; lit = nz;
        } else if (nz < 0xCF) {
            out.push_back(static_cast<uint8_t>(nz + 1));
            tz = 1; lit = nz;
        } else {
            out.push_back(0xD0u);
            tz = 0; lit = nz;
        }
    }
    /* sync_2 EA5T-14D544-BA.sec, IPCMP.dll sub_C0E229B0. */
    out.push_back(kFlag);
    out.push_back(kFlag);
    return out;
}

std::vector<uint8_t> FordSync2VmcuPeer::BuildLinkFrame(uint8_t type, uint8_t tid,
                                                       uint16_t token) {
    /* ipc.dll LINK packet (Cid 0): header(2)=01 00, data(12)=[type][Tid]
       [token:2][config-CRC:4][pad:4]. */
    uint8_t payload[14] = { 0x01u, 0x00u, type, tid };
    Put16(payload + 4, token);
    Put32(payload + 6, kConfigCrc);
    return EncodeFrame(payload, sizeof(payload));
}

std::vector<uint8_t> FordSync2VmcuPeer::BuildAckFrame(uint8_t cid, uint8_t ack_seq) {
    /* ipc.dll transport ACK (SendAck sub_C093B890): a header-only IPCMP packet,
       no data. byte0 = Cid<<2 | 2 (ACK type bit1) -> head RX routes to the RX-ACK
       handler sub_C093BE18; byte1 = next-expected-seq << 1 (the seq the head
       validates against its outstanding TX window); bytes[2..3] = RX window. */
    uint8_t pkt[4] = {
        static_cast<uint8_t>((cid << 2) | 0x02u),
        static_cast<uint8_t>(ack_seq << 1),
    };
    Put16(pkt + 2, kAckWindow);
    return EncodeFrame(pkt, sizeof(pkt));
}

std::vector<uint8_t> FordSync2VmcuPeer::BuildWindowUpdateFrame(uint8_t cid) {
    /* EA5T-14D544-BA.sec, ipc.dll C0938180 (window update), C093D3E0 (receive). */
    uint8_t pkt[4] = { static_cast<uint8_t>((cid << 2) | 0x02u), 1u };
    Put16(pkt + 2, kAckWindow);
    return EncodeFrame(pkt, sizeof(pkt));
}

void FordSync2VmcuPeer::SendPm(const uint8_t* payload6) {
    /* ford_sync_2 pm.dll HandleIPCRx sub_C028AEC0 deframes a 6-byte Cid-8 payload. */
    SendOnCid(kPmCid, pm_tx_seq_, payload6, 6u);
}

void FordSync2VmcuPeer::SendPmSetState(uint8_t state, uint8_t power_status) {
    /* IPC_PM_MSG_SET_PM_STATE (pm.dll HandleSetPMState sub_C028ABD4): State@a1[3],
       PowerStatus@a1[5]. State 0 -> PowerState 4 (Run); 0x10 = InfotainmentPowered. */
    const uint8_t payload[6] = {0x02u, 0x00u, 0x00u, state, 0x00u, power_status};
    SendPm(payload);
}

void FordSync2VmcuPeer::HandlePmRequest() {
    if (pm_state_pushed_) return;
    pm_state_pushed_ = true;
    SendPmSetState(0x00u, 0x10u);
}

void FordSync2VmcuPeer::HandlePmInbound(const uint8_t* pm, std::size_t n) {
    HandlePmRequest();
    const uint8_t tid = pm[1];
    switch (pm[0]) {
        case 0x03u: {
            /* GET_WAKE_SOURCE -> GET_PM_WAKE_SOURCE_COMPLETE (HandleIPCRx case 0x83):
               [0x83][TID][StatusCode=0][_][WS1][WS2]. The consumer
               IPC_GetWakeSourceThread (sub_C028B520) only needs StatusCode=0 to stop
               retrying; WS=0x80 is pm.dll's own normal-wake value (sub_C028809C). */
            const uint8_t reply[6] = {0x83u, tid, 0x00u, 0x00u, 0x80u, 0x80u};
            SendPm(reply);
            break;
        }
        case 0x05u: {
            /* GET_REBOOT_SOURCE -> 0x85 complete (HandleIPCRx case 0x85); StatusCode 0. */
            const uint8_t reply[6] = {0x85u, tid, 0x00u, 0x00u, 0x00u, 0x00u};
            SendPm(reply);
            break;
        }
        case 0x82u:
            /* SET_PM_STATE_COMPLETE: the head's terminal ack of our SET_PM_STATE
               push (pm.dll HandleSetPMState replies 0x82). No VMCU action. */
            break;
        case 0x42u:
            /* ActiveLoad request (IPC_SendALRequest sub_C028A330) - fire-and-forget,
               the head waits for no reply; CERF models no CAN bus to load. */
            break;
        case 0x06u:
            /* PetActivityTimer keep-alive (IPC_PetActivityTimer sub_C028A69C) -
               fire-and-forget; CERF's always-on VMCU has no inactivity timer. */
            break;
        case 0x02u:
            /* IPC_SendRebootRequest (pm.dll sub_C028A22C, AUTOPM sub_C028765C cmd 5). */
            LOG(Caution,
                "Sync 2 has requested reboot over VMCU (pm type=0x%02X len=%zu). "
                "This is a known PANIC reboot, read NKDBG above or debug. Normal case is a corrupted nand.img. "
                "CERF does not restart the guest, so it stays alive for debugging.\n",
                static_cast<unsigned>(pm[0]), n);
#if !CERF_DEV_MODE
            MessageBoxA(nullptr,
                        "Sync 2 has panicked and requested a reboot over VMCU.\n\n"
                        "One possibility is a dirty/corrupted nand.img: delete it "
                        "from the device directory and try flashing again.\n\n"
                        "CERF does not restart the guest, so it "
                        "stays alive for debugging.",
                        "Sync 2 panic reboot - CE Runtime Foundation",
                        MB_OK | MB_ICONWARNING | MB_TASKMODAL | MB_TOPMOST);
#endif
            break;
        default:
            LOG(Caution, "[VMCU] unmodelled inbound pm message type=0x%02X len=%zu\n",
                static_cast<unsigned>(pm[0]), n);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
}

bool FordSync2VmcuPeer::AppendGroundedOidValue(uint32_t oid,
                                               std::vector<uint8_t>& out) {
    switch (oid) {
        /* WERS market letters: VNIGeneralSvc ReadDestinationCode (sub_C15A7364)
           requires each in [A-Z] - an absent value reads as "Invalid WERS code", so
           this is one of the few OIDs whose absence default is wrong. "US" =
           RadioTunerMarket.db DestinationCode row 1 (United States). */
        case 0x002A00A0u: out.push_back('U'); return true;  /* WERSDest1stLetter */
        case 0x002B00A0u: out.push_back('S'); return true;  /* WERSDest2ndLetter */
        default: return false;
    }
}

void FordSync2VmcuPeer::HandleInboundRequest(const uint8_t* inb, std::size_t n) {
    if (n < 2u) return;  /* need at least [type][TID] */
    switch (inb[0]) {
        case 0x02u: HandleInboundGetAllOids(inb, n); break;  /* head reads OIDs */
        case 0x03u: HandleInboundSetOids(inb, n); break;     /* head writes OIDs */
        default:
            LOG(Caution, "[VMCU] unmodelled inbound OID message type=0x%02X len=%zu\n",
                static_cast<unsigned>(inb[0]), n);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
}

void FordSync2VmcuPeer::HandleInboundSetOids(const uint8_t* inb, std::size_t n) {
    (void)n;
    const uint8_t tid = inb[1];
    const uint8_t body[4] = {0x83u, tid, 0x00u, 0x00u};
    SendOnCid(kInboundCid, inbound_tx_seq_, body, sizeof(body));
}

void FordSync2VmcuPeer::HandleInboundGetAllOids(const uint8_t* inb, std::size_t n) {
    if (n < 4u) return;
    const uint8_t tid = inb[1];
    const uint16_t count = U16(inb, 2);
    if (count == 0u || 4u + 4u * static_cast<std::size_t>(count) > n) return;

    /* Answer only OIDs CERF has a grounded value for; omit the rest. An omitted OID
       reads as a miss the guest defaults (readInboundConfig sub_C158441C: absent
       DIAG_OID_CGEA_VERSION -> CGEA1.2) - so CERF never fabricates a value. */
    std::vector<uint8_t> body;
    uint16_t answered = 0u;
    for (uint16_t i = 0; i < count; ++i) {
        const uint32_t oid = U32(inb, 4u + static_cast<std::size_t>(i) * 4u);
        std::vector<uint8_t> val;
        if (!AppendGroundedOidValue(oid, val)) continue;
        Append32(body, oid);
        Append16(body, static_cast<uint16_t>(val.size()));
        body.insert(body.end(), val.begin(), val.end());
        ++answered;
    }
    /* Reply even when answered==0: the guest per-OID GetOIDfromVMCU (sub_C0B15860)
       blocks 1000ms on WaitForSingleObject until a TID-matched reply signals its
       pending event (sub_C0B16BE8), so dropping the empty reply stalls the
       single-threaded HMI AVM 1000ms per ungrounded OID -> watchdog trip, no dashboard. */
    std::vector<uint8_t> reply;
    reply.push_back(0x82u);
    reply.push_back(tid);
    reply.push_back(0x00u);
    reply.push_back(0x00u);
    Append16(reply, answered);
    reply.insert(reply.end(), body.begin(), body.end());
    SendOnCid(kInboundCid, inbound_tx_seq_, reply.data(), reply.size());
}


void FordSync2VmcuPeer::SendOnCid(uint8_t cid, uint8_t& seq, const uint8_t* body,
                                  std::size_t len) {
    InjectReliable(cid, seq, body, len);
    seq = static_cast<uint8_t>((seq + 1u) & 0x7Fu);
}


void FordSync2VmcuPeer::InjectReliable(uint8_t cid, uint8_t seq,
                                       const uint8_t* payload, std::size_t len) {
    std::vector<uint8_t> pkt;
    pkt.push_back(static_cast<uint8_t>((cid << 2) | 0x00u));
    pkt.push_back(static_cast<uint8_t>(seq << 1));
    pkt.insert(pkt.end(), payload, payload + len);
    const auto f = EncodeFrame(pkt.data(), pkt.size());
    uart_->InjectRx(f.data(), f.size());
}

void FordSync2VmcuPeer::OnHeadMessage(uint8_t type) {
    if (type == kMsgSetup) {
        /* Reply with our LINK_SETUP once. The head re-sends LINK_SETUP until
           answered; an extra reply arriving after it reaches state 6 hits
           ipc.dll's RX SM (sub_C093C7EC case 6, msg 1) "Re-starting Link Setup"
           -> DOWN, so LINK UP never completes. */
        if (state_ == PeerState::Down) {
            const auto f = BuildLinkFrame(kMsgSetup, peer_tid_, kPeerToken);
            uart_->InjectRx(f.data(), f.size());
            state_ = PeerState::SetupSent;
        }
    } else if (type == kMsgResp) {
        const auto f = BuildLinkFrame(kMsgCpl, peer_tid_, 0u);
        uart_->InjectRx(f.data(), f.size());
        state_ = PeerState::CplSent;
    }
}

bool FordSync2VmcuPeer::OnHeadData(uint8_t cid, uint8_t rx_seq, bool reliable) {
    /* EA5T-14D544-BA.sec, ipc.dll sub_C093D258 (RX sequence), sub_C093B890 (ACK). */
    const bool accepted = !reliable || rx_seq == next_rx_[cid];
    if (accepted && reliable) next_rx_[cid] = static_cast<uint8_t>((rx_seq + 1u) & 0x7Fu);
    const auto frame = reliable ? BuildAckFrame(cid, next_rx_[cid]) : BuildWindowUpdateFrame(cid);
    uart_->InjectRx(frame.data(), frame.size());
    return accepted;
}

std::size_t FordSync2VmcuPeer::Deframe(const std::vector<uint8_t>& rle,
                                       std::vector<uint8_t>& dec) const {
    /* sync_2 (EA5T-14D544-BA.sec), IPCMP.dll:
       sub_C0E229B0 (RLE), sub_C0E22780 (checksum/trailer), sub_C0E23130 (TX). */
    dec.clear();
    std::size_t i = 0;
    while (i < rle.size()) {
        const uint8_t h = rle[i++];
        std::size_t lit = 0, zr = 0;
        if (h > 0u && h < 0xD0u)          { lit = h - 1;     zr = 1; }
        else if (h == 0xD0u)              { lit = 207;       zr = 0; }
        else if (h >= 0xD3u && h < 0xE0u) { lit = 0;         zr = h & 0xFu; }
        else if (h >= 0xE0u && h < 0xFFu) { lit = h & 0x1Fu; zr = 2; }
        else return 0u;
        if (lit > rle.size() - i) return 0u;
        dec.insert(dec.end(), rle.begin() + i, rle.begin() + i + lit);
        dec.insert(dec.end(), zr, 0u);
        i += lit;
    }
    if (dec.size() < 5u) return 0u;
    const std::size_t n = dec.size() - 3u;
    if (IpcmpChecksum(dec.data(), n) != U16(dec.data(), n)) return 0u;
    dec.resize(n);
    return n;
}

void FordSync2VmcuPeer::OnGuestTx(uint8_t byte) {
    if (byte == kFlag) {
        if (discarding_frame_) { discarding_frame_ = false; tx_frame_.clear(); return; }
        if (!tx_frame_.empty()) {
            std::vector<uint8_t> dec;
            const std::size_t n = Deframe(tx_frame_, dec);
            if (n >= 3 && dec[0] == 0x01u && dec[1] == 0x00u) {
                OnHeadMessage(dec[2]);  /* LINK packet (Cid 0): data[0] = msg type */
            } else if (n >= 2 && (dec[0] >> 2) == kWdgCid && (dec[0] & 3u) == 1u) {
                OnHeadData(kWdgCid, static_cast<uint8_t>(dec[1] >> 1), false);
                emu_.Get<FordSync2IlpChannel>().OnWatchdogPet();
            } else if (n >= 2 && (dec[0] >> 2) > 3u && (dec[0] & 3u) == 0u) {
                const uint8_t cid = static_cast<uint8_t>(dec[0] >> 2);
                if (!OnHeadData(cid, static_cast<uint8_t>(dec[1] >> 1))) {
                    tx_frame_.clear();
                    return;
                }
                if (cid == kInboundCid && n >= 4u) {
                    HandleInboundRequest(&dec[2], n - 2u);
                } else if (cid == kPmCid && n >= 4u) {
                    HandlePmInbound(&dec[2], n - 2u);
                } else if (cid == kIlpCid) {
                    emu_.Get<FordSync2IlpChannel>().HandleInbound(dec.data() + 2, n - 2u);
                } else if (cid == FordSync2VmcuDiagChannel::kCid1 ||
                           cid == FordSync2VmcuDiagChannel::kCid2) {
                    emu_.Get<FordSync2VmcuDiagChannel>().HandleInbound(cid, &dec[2], n - 2u);
                } else {
                    LOG(Caution,
                        "[VMCU] unmodelled inbound data request cid=%u type=0x%02X len=%zu\n",
                        static_cast<unsigned>(cid),
                        static_cast<unsigned>(n >= 3u ? dec[2] : 0u), n);
                    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
                }
            }
            tx_frame_.clear();
        }
        return;
    }
    if (discarding_frame_) return;
    if (tx_frame_.size() >= kMaxTxFrame) {
        discarding_frame_ = true; tx_frame_.clear(); return;
    }
    tx_frame_.push_back(byte);
}

void FordSync2VmcuPeer::SaveState(StateWriter& w) {
    w.Write<uint8_t>(static_cast<uint8_t>(state_));
    w.Write(peer_tid_);
    w.Write(pm_tx_seq_);
    w.Write(inbound_tx_seq_);
    emu_.Get<FordSync2IlpChannel>().SaveState(w);
    w.Write<uint8_t>(pm_state_pushed_ ? 1u : 0u);
    emu_.Get<FordSync2VmcuDiagChannel>().SaveState(w);
    w.WriteBytes(next_rx_.data(), next_rx_.size());
    w.Write<uint8_t>(discarding_frame_);
    w.Write<uint32_t>(static_cast<uint32_t>(tx_frame_.size()));
    w.WriteBytes(tx_frame_.data(), tx_frame_.size());
}

void FordSync2VmcuPeer::RestoreState(StateReader& r) {
    uint8_t s = 0;
    r.Read(s);
    state_ = static_cast<PeerState>(s);
    r.Read(peer_tid_);
    r.Read(pm_tx_seq_);
    r.Read(inbound_tx_seq_);
    emu_.Get<FordSync2IlpChannel>().RestoreState(r);
    uint8_t pushed = 0;
    r.Read(pushed);
    pm_state_pushed_ = pushed != 0u;
    emu_.Get<FordSync2VmcuDiagChannel>().RestoreState(r);
    r.ReadBytes(next_rx_.data(), next_rx_.size());
    uint8_t discarding = 0;
    uint32_t frame_size = 0;
    r.Read(discarding); r.Read(frame_size);
    if (frame_size > kMaxTxFrame) CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    discarding_frame_ = discarding != 0;
    tx_frame_.resize(frame_size);
    r.ReadBytes(tx_frame_.data(), tx_frame_.size());
}

REGISTER_SERVICE(FordSync2VmcuPeer);
