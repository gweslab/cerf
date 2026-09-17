#pragma once

#include "../../core/service.h"
#include "../../socs/uart_endpoint.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

class Imx51Uart2;

/* The SYNC2 companion processor (VMCU) on UART2. Without a peer answering the
   IPC LinkSetup handshake the head unit exhausts LinkSetupMaxRetry and
   watchdog-reboots. Wire codec + election RE'd from IPCMP.dll/ipc.dll. */
class FordSync2VmcuPeer : public Service, public UartEndpoint {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    /* UartEndpoint: a guest UART2 TX byte (JIT thread). Detects the head's IPC
       message type and injects the matching reply. */
    void OnGuestTx(uint8_t byte) override;

    /* Frame a VMCU->head reliable-data packet on a data Cid ([cid<<2|0][seq<<1] +
       payload, IPCMP-encoded) and inject it. Used by the per-channel handler
       services (e.g. FordSync2VmcuDiagChannel) that own their own TX sequence. */
    void InjectReliable(uint8_t cid, uint8_t seq, const uint8_t* payload,
                        std::size_t len);

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    /* Frame delimiter, runtime-read from the IPCMP serial ctx (sub_C0E229B0
       [ctx+20]). Zeros never appear as RLE literals (run-encoded), so 0x00 is
       unambiguous as the delimiter. */
    static constexpr uint8_t  kFlag      = 0x00u;
    /* ipc.dll LINK message: data[0]=type, [1]=Tid, [2..3]=token, [4..7]=CRC. */
    static constexpr uint8_t  kMsgSetup  = 0x01u;
    static constexpr uint8_t  kMsgResp    = 0x81u;
    static constexpr uint8_t  kMsgCpl     = 0x02u;
    static constexpr uint32_t kConfigCrc = 0x3819E683u;  /* ipc.dll a1+264 */
    /* Peer token 0 < head's token (1): head loses the election and sends the
       LINK_RESPONSE itself (ipc.dll sub_C093C7EC state-1 remote<local path). */
    static constexpr uint16_t kPeerToken = 0x0000u;
    /* RX flow-control window the peer advertises in every data ACK (ipc.dll
       SendAck sub_C093B890 reports the RX FIFO free space in bytes[2..3]; the
       head caches it but does not gate the resend release on it). The synthetic
       VMCU always has space, so it reports the protocol max. */
    static constexpr uint16_t kAckWindow = 0xFFFFu;
    /* inbound.dll As-Built OID channel = Cid 38 (IBD_Init sub_C0B16094 *(ctx+32)=38). */
    static constexpr uint8_t  kInboundCid = 38u;
    /* pm.dll power channel = Cid 8 (HandleIPCRx sub_C028AEC0). */
    static constexpr uint8_t  kPmCid      = 8u;
    /* ipc_ilprot ILP signal channel = Cid 28 ($device\ILP, NDIS "IL Protocol";
       DriverEntry sub_C08D7D00 registry IPCDevice=IPC1:). */
    static constexpr uint8_t  kIlpCid     = 28u;
    /* wdg.dll watchdog-pet channel = Cid 4 (registry IPCCID; WDG_Init
       sub_C0951D48). WdgPetWatchdog sub_C09519B0 sends data type 1, not 0. */
    static constexpr uint8_t  kWdgCid     = 4u;

    void OnHeadMessage(uint8_t type);
    /* A reliable data packet the head sent on a data channel (Cid>3): reply with
       the transport ACK that clears the head's TX slot (ipc.dll RX-ACK handler
       sub_C093BE18), so its resend timer (sub_C093C574) stops before MaxResends
       trips "RESEND RETRIES EXPIRED -> RESETTING LINK". */
    bool OnHeadData(uint8_t cid, uint8_t rx_seq, bool reliable = true);
    std::vector<uint8_t> BuildLinkFrame(uint8_t type, uint8_t tid, uint16_t token);
    std::vector<uint8_t> BuildAckFrame(uint8_t cid, uint8_t ack_seq);
    std::vector<uint8_t> BuildWindowUpdateFrame(uint8_t cid);
    /* SET_PM_STATE push (msg 0x02); pm.dll HandleSetPMState sub_C028ABD4. */
    void HandlePmRequest();
    /* pm Cid-8 inbound dispatch; pm.dll HandleIPCRx sub_C028AEC0. */
    void HandlePmInbound(const uint8_t* pm, std::size_t n);
    void SendPmSetState(uint8_t state, uint8_t power_status);
    void SendPm(const uint8_t* payload6);
    /* Cid-38 inbound-OID channel (inbound.dll RX dispatch sub_C0B16CEC). Route on the
       message type: type 2 GetAllOIDsFromVMCU (head reads) and type 3 SendAllOIDsToVMCU
       (head writes its writable set, chunked); FATAL on any other inbound type. */
    void HandleInboundRequest(const uint8_t* inb, std::size_t n);
    /* type-2 GetAllOIDsFromVMCU (sub_C0B15CDC): answer the OIDs CERF has a grounded
       value for; omit the rest (the guest defaults them). Reply type-130 OID-DATA. */
    void HandleInboundGetAllOids(const uint8_t* inb, std::size_t n);
    /* type-3 SendAllOIDsToVMCU (sub_C0B15A54): the head pushes its writable OID set in
       chunks and waits for a per-batch completion before sending the next (the RX
       dispatcher sub_C0B16CEC case 131 re-arms sub_C0B15A54 on a TID match). Reply
       type-131 [0x83][TID][StatusCode=0] (success) so the head advances every batch. */
    void HandleInboundSetOids(const uint8_t* inb, std::size_t n);
    /* Append the grounded As-Built value for one OID; false if none (OID omitted). */
    bool AppendGroundedOidValue(uint32_t oid, std::vector<uint8_t>& out);
    void SendOnCid(uint8_t cid, uint8_t& seq, const uint8_t* body, std::size_t len);
    /* IPCMP wire framing shared by the link + ack packets (IPCMP.dll builder
       sub_C0E23130 + framer sub_C0E22C40): append the 16-bit additive checksum
       over the payload, then its 3-byte [lo][hi][00] segment, RLE-encode the whole
       thing, and FLAG-frame it (00 <rle> 00 00). */
    std::vector<uint8_t> EncodeFrame(const uint8_t* payload, std::size_t len);
    std::size_t Deframe(const std::vector<uint8_t>& rle,
                        std::vector<uint8_t>& dec) const;

    Imx51Uart2* uart_ = nullptr;

    enum class PeerState { Down, SetupSent, CplSent };
    PeerState state_ = PeerState::Down;
    uint8_t   peer_tid_ = 1u;

    /* The VMCU's own monotonic TX sequence on the Cid-38 inbound OID channel. */
    uint8_t   inbound_tx_seq_ = 0u;
    uint8_t   pm_tx_seq_ = 0u;
    bool      pm_state_pushed_ = false;

    /* Guest TX bytes between FLAG (0x00) delimiters; deframed on each FLAG to
       read the message type (LINK_SETUP 0x01 / LINK_RESPONSE 0x81). A valid IPC
       frame is <= MaxTxFrameSize (4105, runtime IPC config); exceeding kMaxTxFrame
       means an unterminated stream, and the accumulator resyncs at the next FLAG. */
    static constexpr std::size_t kMaxTxFrame = 8192u;
    std::vector<uint8_t> tx_frame_;
    std::array<uint8_t, 64> next_rx_{};
    bool discarding_frame_ = false;
};
