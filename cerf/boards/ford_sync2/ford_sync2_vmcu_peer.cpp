#if !CERF_DEV_MODE
#define NOMINMAX
#include <windows.h>
#endif

#include "ford_sync2_vmcu_peer.h"

#include "ford_sync2_vmcu_diag_channel.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../socs/imx51/imx51_uart2.h"
#include "../../state/state_stream.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

bool FordSync2VmcuPeer::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoard() == Board::FordSyncGen2;
}

void FordSync2VmcuPeer::OnReady() {
    uart_ = &emu_.Get<Imx51Uart2>();
    uart_->AttachEndpoint(this);
}

std::vector<uint8_t> FordSync2VmcuPeer::EncodeFrame(const uint8_t* payload,
                                                    std::size_t len) {
    /* 16-bit additive checksum over the payload (header+data), little-endian,
       followed by a 0 pad: IPCMP frames the checksum as a 3-byte segment
       [ck_lo][ck_hi][00] (sub_C0E23130 *(v22+24)=3 segments). */
    uint32_t sum = 0u;
    for (std::size_t i = 0; i < len; ++i) sum += payload[i];
    sum &= 0xFFFFu;

    std::vector<uint8_t> flat(payload, payload + len);
    flat.push_back(static_cast<uint8_t>(sum & 0xFFu));
    flat.push_back(static_cast<uint8_t>(sum >> 8));
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
            /* A zero header encodes <=15 zeros (0xDF); chunk the run so a run >15B
               doesn't desync the deframer (sub_C0E229B0) into seeing only 15. */
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
    /* FLAG <rle> FLAG FLAG: the deframer (sub_C0E229B0) dispatches a buffer only
       on a FLAG FLAG double-delimiter; a single trailing FLAG leaves it pending. */
    out.push_back(kFlag);
    out.push_back(kFlag);
    return out;
}

std::vector<uint8_t> FordSync2VmcuPeer::BuildLinkFrame(uint8_t type, uint8_t tid,
                                                       uint16_t token) {
    /* ipc.dll LINK packet (Cid 0): header(2)=01 00, data(12)=[type][Tid]
       [token:2][config-CRC:4][pad:4]. */
    const uint8_t payload[14] = {
        0x01u, 0x00u,
        type, tid,
        static_cast<uint8_t>(token & 0xFFu), static_cast<uint8_t>(token >> 8),
        static_cast<uint8_t>(kConfigCrc & 0xFFu),
        static_cast<uint8_t>((kConfigCrc >> 8) & 0xFFu),
        static_cast<uint8_t>((kConfigCrc >> 16) & 0xFFu),
        static_cast<uint8_t>((kConfigCrc >> 24) & 0xFFu),
        0u, 0u, 0u, 0u,
    };
    return EncodeFrame(payload, sizeof(payload));
}

std::vector<uint8_t> FordSync2VmcuPeer::BuildAckFrame(uint8_t cid, uint8_t ack_seq) {
    /* ipc.dll transport ACK (SendAck sub_C093B890): a header-only IPCMP packet,
       no data. byte0 = Cid<<2 | 2 (ACK type bit1) -> head RX routes to the RX-ACK
       handler sub_C093BE18; byte1 = next-expected-seq << 1 (the seq the head
       validates against its outstanding TX window); bytes[2..3] = RX window. */
    const uint8_t pkt[4] = {
        static_cast<uint8_t>((cid << 2) | 0x02u),
        static_cast<uint8_t>(ack_seq << 1),
        static_cast<uint8_t>(kAckWindow & 0xFFu),
        static_cast<uint8_t>(kAckWindow >> 8),
    };
    return EncodeFrame(pkt, sizeof(pkt));
}

std::vector<uint8_t> FordSync2VmcuPeer::BuildPmFrame(const uint8_t* payload6) {
    /* Cid-8 reliable-data frame: [cid<<2|type0][seq<<1] + the 6-byte pm payload
       the head deframes for HandleIPCRx (sub_C028AEC0). */
    const uint8_t pkt[8] = {
        static_cast<uint8_t>((kPmCid << 2) | 0x00u),
        static_cast<uint8_t>(pm_tx_seq_ << 1),
        payload6[0], payload6[1], payload6[2], payload6[3], payload6[4], payload6[5],
    };
    pm_tx_seq_ = static_cast<uint8_t>((pm_tx_seq_ + 1u) & 0x7Fu);
    return EncodeFrame(pkt, sizeof(pkt));
}

std::vector<uint8_t> FordSync2VmcuPeer::BuildPmSetState(uint8_t state,
                                                        uint8_t power_status) {
    /* IPC_PM_MSG_SET_PM_STATE (pm.dll HandleSetPMState sub_C028ABD4): State@a1[3],
       PowerStatus@a1[5]. State 0 -> PowerState 4 (Run); 0x10 = InfotainmentPowered. */
    const uint8_t payload[6] = {0x02u, 0x00u, 0x00u, state, 0x00u, power_status};
    return BuildPmFrame(payload);
}

void FordSync2VmcuPeer::HandlePmRequest() {
    if (pm_state_pushed_) return;
    pm_state_pushed_ = true;
    const auto f = BuildPmSetState(0x00u, 0x10u);
    uart_->InjectRx(f.data(), f.size());
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
            const auto f = BuildPmFrame(reply);
            uart_->InjectRx(f.data(), f.size());
            break;
        }
        case 0x05u: {
            /* GET_REBOOT_SOURCE -> 0x85 complete (HandleIPCRx case 0x85); StatusCode 0. */
            const uint8_t reply[6] = {0x85u, tid, 0x00u, 0x00u, 0x00u, 0x00u};
            const auto f = BuildPmFrame(reply);
            uart_->InjectRx(f.data(), f.size());
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
                "This is a known PANIC reboot, read NKDBG above or debug. Normal case is a corrupted nand.img\n",
                static_cast<unsigned>(pm[0]), n);
#if !CERF_DEV_MODE
            MessageBoxA(nullptr,
                        "Sync 2 has requested a reboot over VMCU, but this is a "
                        "known panic reboot - something went wrong.\n\n"
                        "One possibility is a dirty/corrupted nand.img: delete it "
                        "from the device directory and try flashing again.\n\n"
                        "If that does not help, you have hit something genuinely "
                        "else that is not fixable on your side.",
                        "Sync 2 panic reboot - CE Runtime Foundation",
                        MB_OK | MB_ICONERROR | MB_TASKMODAL | MB_TOPMOST);
#endif
            CerfFatalExit(CERF_FATAL_USER_ERROR);
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
    const uint8_t pkt[6] = {
        static_cast<uint8_t>((kInboundCid << 2) | 0x00u),
        static_cast<uint8_t>(inbound_tx_seq_ << 1),
        0x83u,
        tid,
        0x00u,
        0x00u,
    };
    inbound_tx_seq_ = static_cast<uint8_t>((inbound_tx_seq_ + 1u) & 0x7Fu);
    const auto f = EncodeFrame(pkt, sizeof(pkt));
    uart_->InjectRx(f.data(), f.size());
}

void FordSync2VmcuPeer::HandleInboundGetAllOids(const uint8_t* inb, std::size_t n) {
    if (n < 4u) return;
    const uint8_t tid = inb[1];
    const uint16_t count = static_cast<uint16_t>(inb[2] | (inb[3] << 8));
    if (count == 0u || 4u + 4u * static_cast<std::size_t>(count) > n) return;

    /* Answer only OIDs CERF has a grounded value for; omit the rest. An omitted OID
       reads as a miss the guest defaults (readInboundConfig sub_C158441C: absent
       DIAG_OID_CGEA_VERSION -> CGEA1.2) - so CERF never fabricates a value. */
    std::vector<uint8_t> body;
    uint16_t answered = 0u;
    for (uint16_t i = 0; i < count; ++i) {
        const uint8_t* o = inb + 4u + static_cast<std::size_t>(i) * 4u;
        const uint32_t oid = static_cast<uint32_t>(o[0]) |
                             (static_cast<uint32_t>(o[1]) << 8) |
                             (static_cast<uint32_t>(o[2]) << 16) |
                             (static_cast<uint32_t>(o[3]) << 24);
        std::vector<uint8_t> val;
        if (!AppendGroundedOidValue(oid, val)) continue;
        body.push_back(o[0]); body.push_back(o[1]); body.push_back(o[2]); body.push_back(o[3]);
        body.push_back(static_cast<uint8_t>(val.size() & 0xFFu));
        body.push_back(static_cast<uint8_t>(val.size() >> 8));
        body.insert(body.end(), val.begin(), val.end());
        ++answered;
    }
    /* Reply even when answered==0: the guest per-OID GetOIDfromVMCU (sub_C0B15860)
       blocks 1000ms on WaitForSingleObject until a TID-matched reply signals its
       pending event (sub_C0B16BE8), so dropping the empty reply stalls the
       single-threaded HMI AVM 1000ms per ungrounded OID -> watchdog trip, no dashboard. */
    std::vector<uint8_t> pkt;
    pkt.push_back(static_cast<uint8_t>((kInboundCid << 2) | 0x00u));
    pkt.push_back(static_cast<uint8_t>(inbound_tx_seq_ << 1));
    inbound_tx_seq_ = static_cast<uint8_t>((inbound_tx_seq_ + 1u) & 0x7Fu);
    pkt.push_back(0x82u);
    pkt.push_back(tid);
    pkt.push_back(0x00u);
    pkt.push_back(0x00u);
    pkt.push_back(static_cast<uint8_t>(answered & 0xFFu));
    pkt.push_back(static_cast<uint8_t>(answered >> 8));
    pkt.insert(pkt.end(), body.begin(), body.end());
    const auto f = EncodeFrame(pkt.data(), pkt.size());
    uart_->InjectRx(f.data(), f.size());
}

std::vector<uint8_t> FordSync2VmcuPeer::BuildIlpComplete(uint8_t req_type, uint16_t tid) {
    /* Cid-28 reliable-data frame [cid<<2|0][seq<<1] + the 4-byte completion payload the
       head RX dispatcher (sub_C08DC334) deframes: [respType=req_type|0x80][StatusCode]
       [TID_lo][TID_hi]. It matches a2[2..3] against the waiting slot's TID (slot+52) and
       reads a2[1] as the StatusCode; 0 = success (sub_C08D9A10/sub_C08D9468 accept 0/64). */
    const uint8_t pkt[6] = {
        static_cast<uint8_t>((kIlpCid << 2) | 0x00u),
        static_cast<uint8_t>(ilp_tx_seq_ << 1),
        static_cast<uint8_t>(req_type | 0x80u),
        0x00u,
        static_cast<uint8_t>(tid & 0xFFu),
        static_cast<uint8_t>(tid >> 8),
    };
    ilp_tx_seq_ = static_cast<uint8_t>((ilp_tx_seq_ + 1u) & 0x7Fu);
    return EncodeFrame(pkt, sizeof(pkt));
}

std::vector<uint8_t> FordSync2VmcuPeer::BuildIlpGetAssocNone(uint16_t tid) {
    /* Cid-28 reliable-data frame + the type-132 GetSignalsAssoc response the head RX
       dispatcher (sub_C08DC334 case 132) deframes: [0x84][StatusCode][TID_lo][TID_hi]
       [NumSignals_lo][NumSignals_hi]. NumSignals=0 = no associations available. */
    const uint8_t pkt[8] = {
        static_cast<uint8_t>((kIlpCid << 2) | 0x00u),
        static_cast<uint8_t>(ilp_tx_seq_ << 1),
        0x84u,
        0x00u,
        static_cast<uint8_t>(tid & 0xFFu),
        static_cast<uint8_t>(tid >> 8),
        0x00u,
        0x00u,
    };
    ilp_tx_seq_ = static_cast<uint8_t>((ilp_tx_seq_ + 1u) & 0x7Fu);
    return EncodeFrame(pkt, sizeof(pkt));
}

void FordSync2VmcuPeer::HandleIlpInbound(const uint8_t* ilp, std::size_t n) {
    /* ilp[0] = request type, ilp[2..3] = 16-bit TID. */
    if (n < 4u) return;
    const uint8_t req_type = ilp[0];
    const uint16_t tid = static_cast<uint16_t>(ilp[2] | (ilp[3] << 8));
    switch (req_type) {
        /* type 2 SetSignalsAssoc (sub_C08DD9A0) / 5 SendFilterOverIPC (sub_C08D9A10) /
           6 SendRegisterSignalNotification (sub_C08D9468): reliable transactions the head
           blocks on; reply the 4-byte TID-keyed completion. */
        case 0x02u:
        case 0x05u:
        case 0x06u: {
            const auto f = BuildIlpComplete(req_type, tid);
            uart_->InjectRx(f.data(), f.size());
            break;
        }
        case 0x04u: {  /* GetSignalsAssoc (sub_C08DE3A4): synchronous value read, none held */
            const auto f = BuildIlpGetAssocNone(tid);
            uart_->InjectRx(f.data(), f.size());
            break;
        }
        default: {
            char hex[3 * 32 + 1]; int o = 0;
            for (std::size_t i = 0; i < n && i < 32 && o < (int)sizeof(hex) - 3; ++i)
                o += std::snprintf(hex + o, sizeof(hex) - o, "%02X ", ilp[i]);
            LOG(Caution, "[VMCU] unmodelled inbound ILP transaction type=0x%02X len=%zu: %s\n",
                static_cast<unsigned>(req_type), n, hex);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
    }
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

void FordSync2VmcuPeer::OnHeadData(uint8_t cid, uint8_t rx_seq) {
    /* ACK the next-expected sequence (ipc.dll SendAck advances ES past the
       received seq before sending: byte1 = (rx_seq+1) mod 128). */
    const uint8_t ack_seq = static_cast<uint8_t>((rx_seq + 1u) & 0x7Fu);
    const auto f = BuildAckFrame(cid, ack_seq);
    uart_->InjectRx(f.data(), f.size());
}

std::size_t FordSync2VmcuPeer::Deframe(const std::vector<uint8_t>& rle, uint8_t* dec,
                                       std::size_t cap) const {
    /* RLE headers per the deframer sub_C0E229B0: <0xD0 = (H-1) literals + 1
       zero; 0xD0 = 207 literals; 0xD3..0xDF = (H&0xF) zeros; 0xE0..0xFE =
       (H&0x1F) literals + 2 zeros. */
    std::size_t n = 0, i = 0;
    while (i < rle.size() && n < cap) {
        const uint8_t h = rle[i++];
        int lit = 0, zr = 0;
        if (h < 0xD0u)                    { lit = h - 1;     zr = 1; }
        else if (h == 0xD0u)              { lit = 207;       zr = 0; }
        else if (h >= 0xD3u && h < 0xE0u) { lit = 0;         zr = h & 0xFu; }
        else if (h >= 0xE0u && h < 0xFFu) { lit = h & 0x1Fu; zr = 2; }
        else return 0u;  /* 0xD1 / 0xD2 / 0xFF = malformed */
        for (int k = 0; k < lit && i < rle.size() && n < cap; ++k)
            dec[n++] = rle[i++];
        for (int k = 0; k < zr && n < cap; ++k) dec[n++] = 0u;
    }
    return n;
}

void FordSync2VmcuPeer::OnGuestTx(uint8_t byte) {
    if (byte == kFlag) {
        if (!tx_frame_.empty()) {
            /* Decode just enough to route on the transport header (Cid/type at
               [0], seq at [1], LINK msg type at [2]); the data-channel payloads
               themselves are not parsed here. */
            uint8_t dec[64] = {0};
            const std::size_t n = Deframe(tx_frame_, dec, sizeof(dec));
            if (n >= 3 && dec[0] == 0x01u && dec[1] == 0x00u) {
                OnHeadMessage(dec[2]);  /* LINK packet (Cid 0): data[0] = msg type */
            } else if (n >= 2 && (dec[0] >> 2) > 3u && (dec[0] & 3u) == 0u) {
                const uint8_t cid = static_cast<uint8_t>(dec[0] >> 2);
                OnHeadData(cid, static_cast<uint8_t>(dec[1] >> 1));
                if (cid == kInboundCid && n >= 4u) {
                    HandleInboundRequest(&dec[2], n - 2u);
                } else if (cid == kPmCid && n >= 4u) {
                    HandlePmInbound(&dec[2], n - 2u);
                } else if (cid == kIlpCid && n >= 6u) {
                    HandleIlpInbound(&dec[2], n - 2u);
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
    if (tx_frame_.size() >= kMaxTxFrame) tx_frame_.clear();
    tx_frame_.push_back(byte);
}

void FordSync2VmcuPeer::SaveState(StateWriter& w) {
    w.Write<uint8_t>(static_cast<uint8_t>(state_));
    w.Write(peer_tid_);
    w.Write(pm_tx_seq_);
    w.Write(inbound_tx_seq_);
    w.Write(ilp_tx_seq_);
    w.Write<uint8_t>(pm_state_pushed_ ? 1u : 0u);
    emu_.Get<FordSync2VmcuDiagChannel>().SaveState(w);
}

void FordSync2VmcuPeer::RestoreState(StateReader& r) {
    uint8_t s = 0;
    r.Read(s);
    state_ = static_cast<PeerState>(s);
    r.Read(peer_tid_);
    r.Read(pm_tx_seq_);
    r.Read(inbound_tx_seq_);
    r.Read(ilp_tx_seq_);
    uint8_t pushed = 0;
    r.Read(pushed);
    pm_state_pushed_ = pushed != 0u;
    emu_.Get<FordSync2VmcuDiagChannel>().RestoreState(r);
}

REGISTER_SERVICE(FordSync2VmcuPeer);
