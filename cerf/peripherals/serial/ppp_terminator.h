#pragma once

#include "ppp_hdlc.h"
#include "../../net/mac_address.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

class CerfEmulator;
class SerialLine;

/* LCP per RFC 1661; IPCP per RFC 1332. */
class PppTerminator {
public:
    PppTerminator(CerfEmulator& emu, SerialLine& uart, std::string net_id);
    ~PppTerminator();

    void Start();   /* carrier up: begin a session, install host RX callback */
    void Stop();    /* carrier down / hangup: remove RX callback, reset state */

    void OnGuestData(const uint8_t* data, size_t n);   /* online-mode guest TX */
    void SetRts(bool on);                              /* guest RTS flow control */

private:
    void OnPppFrame(uint16_t proto, const uint8_t* p, size_t len);
    void HandleConfProto(uint16_t proto, const uint8_t* p, size_t len);
    void HandleLcpConfReq(uint8_t id, const uint8_t* opts, size_t len);
    void HandleIpcpConfReq(uint8_t id, const uint8_t* opts, size_t len);
    void HandleGuestIp(const uint8_t* ip, size_t len);      /* guest -> slirp */
    void OnHostFrame(const uint8_t* eth, size_t len);       /* slirp -> guest */
    void HandleArp(const uint8_t* eth, size_t len);

    void SendCp(uint16_t proto, uint8_t code, uint8_t id,
                const uint8_t* data, size_t len);
    void SendLcpConfReq();
    void SendIpcpConfReq();
    void SendPpp(uint16_t proto, const uint8_t* p, size_t len);
    void MaybeOpenLcp();
    void MaybeOpenIpcp();

    /* Outbound frames to libslirp are queued under out_mu_ and sent by DrainTx
       on the JIT thread while holding neither mu_ nor slirp's lock - calling
       SendFrame under mu_ (or from the RX path under slirp's lock) deadlocks
       against the poll thread (slirp_mutex_ <-> mu_). */
    void QueueTx(std::vector<uint8_t> frame);
    void DrainTx();
    void BuildGratuitousArp(std::vector<uint8_t>& out) const;

    /* Feed one held RX frame to the UART when RTS is asserted and the UART has
       drained - paces delivery to the guest's serial buffer. */
    void Pump();
    void PumpLocked();

    CerfEmulator& emu_;
    std::string   net_id_;
    SerialLine&   uart_;
    PppHdlc       hdlc_;
    std::mutex    mu_;   /* locked only at the public entry points */

    bool active_ = false;

    bool    lcp_open_      = false;
    bool    lcp_peer_acked_ = false;   /* peer ACKed our LCP ConfReq */
    bool    lcp_we_acked_   = false;   /* we ACKed peer's LCP ConfReq */
    uint8_t lcp_req_id_     = 0;

    /* RFC 1662 §7.1: on asynchronous links the default receiving ACCM is
       0xffffffff, so a narrower map holds only once negotiated. */
    uint32_t negotiated_tx_accm_ = 0xFFFFFFFFu;

    bool    ipcp_open_      = false;
    bool    ipcp_peer_acked_ = false;
    bool    ipcp_we_acked_   = false;
    uint8_t ipcp_req_id_    = 0;

    uint8_t next_id_ = 1;

    cerf::inet::MacAddress guest_mac_{};
    cerf::inet::MacAddress gw_mac_{};

    std::mutex                        out_mu_;     /* leaf lock, never nested */
    std::vector<std::vector<uint8_t>> outbound_;

    /* Guest-bound frames queue in rx_hold_ and are fed to the UART one at a
       time, only while the guest asserts RTS and the UART RX has drained - RTS
       flow control + pacing to the guest's serial buffer. Under mu_. */
    bool                              rts_ = true;
    std::vector<std::vector<uint8_t>> rx_hold_;
};
