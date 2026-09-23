#include "ppp_terminator.h"

#include "serial_line.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../net/ipv4_packet.h"
#include "../../net/network_backend.h"

#include <cstring>

/* PPP Protocol field hex c021 = Link Control Protocol (RFC 1661), hex 8021
   = IP Control Protocol (RFC 1332). */
namespace {

constexpr uint16_t kProtoLcp  = 0xC021;
constexpr uint16_t kProtoIpcp = 0x8021;
constexpr uint16_t kProtoIp   = 0x0021;

constexpr uint8_t kConfReq = 1, kConfAck = 2, kConfNak = 3, kConfRej = 4;
constexpr uint8_t kTermReq = 5, kTermAck = 6, kCodeRej = 7;
constexpr uint8_t kProtoRej = 8, kEchoReq = 9, kEchoRep = 10;
constexpr uint8_t kLcpMru = 1, kLcpAccm = 2, kLcpAuth = 3, kLcpMagic = 5,
                  kLcpPfc = 7, kLcpAcfc = 8;
constexpr uint8_t kIpcpComp = 2, kIpcpAddr = 3, kIpcpDns = 129,
                  kIpcpWins = 130;

/* IPCP hands these to the guest; they must equal libslirp's configured guest /
   gateway / DNS addresses or traffic will not route. */
const uint8_t kGuestIp[4] = {10, 0, 2, 15};
const uint8_t kGwIp[4]    = {10, 0, 2, 2};
const uint8_t kDnsIp[4]   = {10, 0, 2, 3};

constexpr uint16_t kArpHtypeEthernet = 0x0001;
constexpr uint16_t kArpOperRequest   = 0x0001;
constexpr uint16_t kArpOperReply     = 0x0002;

using cerf::be::Append16;
using cerf::be::Put16;
using cerf::be::U16;
using cerf::be::U32;
using namespace cerf::inet;

void AppendArpFrame(std::vector<uint8_t>& out, const uint8_t* eth_dst,
                    const uint8_t* sender_mac, uint16_t oper,
                    const uint8_t* target_mac, const uint8_t* target_ip) {
    AppendEthHeader(out, eth_dst, sender_mac, kEthTypeArp);
    const size_t at = out.size();
    out.resize(at + kArpPacketSize);
    uint8_t* arp = out.data() + at;
    Put16(arp + kArpOffHtype, kArpHtypeEthernet);
    Put16(arp + kArpOffPtype, kEthTypeIpv4);
    arp[kArpOffHlen] = uint8_t(kEthMacSize);
    arp[kArpOffPlen] = uint8_t(kIpv4AddrSize);
    Put16(arp + kArpOffOper, oper);
    std::memcpy(arp + kArpOffSenderMac, sender_mac, kEthMacSize);
    std::memcpy(arp + kArpOffSenderIp, kGuestIp, kIpv4AddrSize);
    std::memcpy(arp + kArpOffTargetMac, target_mac, kEthMacSize);
    std::memcpy(arp + kArpOffTargetIp, target_ip, kIpv4AddrSize);
}

}  /* namespace */

PppTerminator::PppTerminator(CerfEmulator& emu, SerialLine& uart, std::string net_id)
    : emu_(emu), net_id_(std::move(net_id)), uart_(uart) {
    hdlc_.SetFrameSink([this](uint16_t proto, const uint8_t* p, size_t len) {
        OnPppFrame(proto, p, len);
    });
    uart_.SetRxDrainCallback([this] { Pump(); });
}

PppTerminator::~PppTerminator() {
    uart_.SetRxDrainCallback(nullptr);   /* JIT thread stopped at shutdown */
    Stop();
}

void PppTerminator::Start() {
    auto& net = emu_.Get<NetworkBackend>();
    const cerf::inet::MacAddress mac =
        net.MacForReceiver(net_id_, NetworkBackend::ReceiverKind::PointToPoint);
    {
        std::lock_guard<std::mutex> lk(mu_);
        guest_mac_ = mac;
        gw_mac_    = net.HostGatewayMacAddress();
        hdlc_      = PppHdlc{};
        hdlc_.SetFrameSink([this](uint16_t proto, const uint8_t* p, size_t len) {
            OnPppFrame(proto, p, len);
        });
        lcp_open_ = lcp_peer_acked_ = lcp_we_acked_ = false;
        ipcp_open_ = ipcp_peer_acked_ = ipcp_we_acked_ = false;
        lcp_req_id_ = ipcp_req_id_ = 0;
        negotiated_tx_accm_ = 0xFFFFFFFFu;
        next_id_ = 1;
        rts_ = true;
        rx_hold_.clear();
        active_ = true;
    }
    { std::lock_guard<std::mutex> lk(out_mu_); outbound_.clear(); }
    net.AttachReceiver(net_id_, NetworkBackend::ReceiverKind::PointToPoint,
                       [this](const uint8_t* eth, size_t len) {
                           OnHostFrame(eth, len);
                       });
    LOG(Net, "[PPP] session start (guest=10.0.2.15 gw=10.0.2.2 dns=10.0.2.3)\n");
}

void PppTerminator::Stop() {
    auto* net = emu_.TryGet<NetworkBackend>();
    if (net) net->DetachReceiver(net_id_);
    std::lock_guard<std::mutex> lk(mu_);
    if (!active_) return;
    active_ = false;
    lcp_open_ = ipcp_open_ = false;
    rx_hold_.clear();
    LOG(Net, "[PPP] session stop\n");
}

void PppTerminator::OnGuestData(const uint8_t* data, size_t n) {
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (!active_) return;
        hdlc_.Feed(data, n);   /* may QueueTx via HandleGuestIp / MaybeOpenIpcp */
    }
    DrainTx();                 /* send outside mu_ - see QueueTx note */
}

/* ---- guest -> us (under mu_ via OnGuestData) ---- */

void PppTerminator::OnPppFrame(uint16_t proto, const uint8_t* p, size_t len) {
    if (proto == kProtoLcp || proto == kProtoIpcp) {
        HandleConfProto(proto, p, len);
    } else if (proto == kProtoIp) {
        HandleGuestIp(p, len);
    } else if (lcp_open_) {
        /* RFC 1661 Protocol-Reject: data = the rejected protocol (2B) + its
           payload. */
        std::vector<uint8_t> d;
        Append16(d, proto);
        d.insert(d.end(), p, p + len);
        SendCp(kProtoLcp, kProtoRej, next_id_++, d.data(), d.size());
    }
}

void PppTerminator::HandleConfProto(uint16_t proto, const uint8_t* p,
                                    size_t len) {
    if (len < 4) return;
    const uint8_t code = p[0];
    const uint8_t id   = p[1];
    size_t plen = U16(p, 2);
    if (plen < 4 || plen > len) plen = len;
    const uint8_t* data = p + 4;
    const size_t   dlen = plen - 4;

    const bool is_lcp = (proto == kProtoLcp);

    if (code != kEchoReq && code != kEchoRep)
        LOG(Net, "[PPP] rx %s code=%u id=%u dlen=%zu\n",
            is_lcp ? "LCP" : "IPCP", code, id, dlen);

    switch (code) {
        case kConfReq:
            if (is_lcp) HandleLcpConfReq(id, data, dlen);
            else        HandleIpcpConfReq(id, data, dlen);
            if (is_lcp) { if (!lcp_req_id_) SendLcpConfReq(); }
            else        { if (!ipcp_req_id_) SendIpcpConfReq(); }
            break;
        case kConfAck:
            if (is_lcp && id == lcp_req_id_)  { lcp_peer_acked_ = true;  MaybeOpenLcp(); }
            if (!is_lcp && id == ipcp_req_id_){ ipcp_peer_acked_ = true; MaybeOpenIpcp(); }
            break;
        case kConfNak:
        case kConfRej:
            /* Our ConfReqs carry only options the CE peer always accepts (LCP:
               none; IPCP: our gateway address), so a Nak/Rej is not expected;
               re-send the same request to make progress. */
            if (is_lcp)  SendLcpConfReq();
            else         SendIpcpConfReq();
            break;
        case kTermReq:
            SendCp(proto, kTermAck, id, data, dlen);
            if (is_lcp) { lcp_open_ = false; ipcp_open_ = false; }
            else        ipcp_open_ = false;
            break;
        case kEchoReq:
            if (is_lcp && lcp_open_) {
                std::vector<uint8_t> d(4, 0);   /* our Magic-Number = 0 */
                if (dlen > 4) d.insert(d.end(), data + 4, data + dlen);
                SendCp(kProtoLcp, kEchoRep, id, d.data(), d.size());
            }
            break;
        case kTermAck:
        case kCodeRej:
        case kProtoRej:
        case kEchoRep:
        default:
            break;
    }
}

void PppTerminator::HandleLcpConfReq(uint8_t id, const uint8_t* opts,
                                     size_t len) {
    /* Configure-Reject per RFC 1661 §5.4. */
    std::vector<uint8_t> rej;
    size_t i = 0;
    while (i + 2 <= len) {
        const uint8_t type = opts[i];
        const uint8_t olen = opts[i + 1];
        if (olen < 2 || i + olen > len) break;
        const uint8_t* val = opts + i + 2;
        const size_t   vlen = olen - 2u;

        bool reject = false;
        switch (type) {
            case kLcpMru: case kLcpPfc: case kLcpAcfc: break;          /* ACK */
            case kLcpAccm:
                if (vlen == 4) {
                    negotiated_tx_accm_ = U32(val);
                }
                break;
            case kLcpMagic:
                if (vlen == 4 && val[0] == 0 && val[1] == 0 &&
                    val[2] == 0 && val[3] == 0) reject = true;
                break;
            case kLcpAuth:
            default: reject = true; break;
        }
        if (reject) rej.insert(rej.end(), opts + i, opts + i + olen);
        i += olen;
    }

    if (!rej.empty()) {
        SendCp(kProtoLcp, kConfRej, id, rej.data(), rej.size());
    } else {
        SendCp(kProtoLcp, kConfAck, id, opts, len);
        lcp_we_acked_ = true;
        MaybeOpenLcp();
    }
}

void PppTerminator::HandleIpcpConfReq(uint8_t id, const uint8_t* opts,
                                      size_t len) {
    std::vector<uint8_t> rej, nak;
    size_t i = 0;
    while (i + 2 <= len) {
        const uint8_t type = opts[i];
        const uint8_t olen = opts[i + 1];
        if (olen < 2 || i + olen > len) break;
        const uint8_t* val = opts + i + 2;
        const size_t   vlen = olen - 2u;

        auto nak_addr = [&](const uint8_t ip[4]) {
            nak.push_back(type); nak.push_back(6);
            nak.insert(nak.end(), ip, ip + 4);
        };

        if (type == kIpcpAddr && vlen == 4) {
            if (std::memcmp(val, kGuestIp, 4) != 0) nak_addr(kGuestIp);
        } else if (type == kIpcpDns && vlen == 4) {
            if (std::memcmp(val, kDnsIp, 4) != 0) nak_addr(kDnsIp);
        } else {
            rej.insert(rej.end(), opts + i, opts + i + olen);  /* VJ, WINS, … */
        }
        i += olen;
    }

    if (!rej.empty())      SendCp(kProtoIpcp, kConfRej, id, rej.data(), rej.size());
    else if (!nak.empty()) SendCp(kProtoIpcp, kConfNak, id, nak.data(), nak.size());
    else {
        SendCp(kProtoIpcp, kConfAck, id, opts, len);
        ipcp_we_acked_ = true;
        MaybeOpenIpcp();
    }
}

void PppTerminator::MaybeOpenLcp() {
    if (lcp_open_ || !lcp_peer_acked_ || !lcp_we_acked_) return;
    lcp_open_ = true;
    hdlc_.SetTxAccm(negotiated_tx_accm_);   /* both ends Open: safe to relax */
    LOG(Net, "[PPP] LCP up\n");
}

void PppTerminator::MaybeOpenIpcp() {
    if (ipcp_open_ || !ipcp_peer_acked_ || !ipcp_we_acked_) return;
    ipcp_open_ = true;
    LOG(Net, "[PPP] IPCP up - guest is online\n");
    /* Announce guest_ip -> guest_mac: libslirp learns MACs only from ARP input
       (slirp.c:1205), never from IP frames, so without this it would ARP the
       guest to deliver the first reply - which our RX path cannot answer
       without re-entering slirp's lock. */
    std::vector<uint8_t> arp;
    BuildGratuitousArp(arp);
    QueueTx(std::move(arp));
}

void PppTerminator::SendLcpConfReq() {
    lcp_req_id_ = next_id_++;
    SendCp(kProtoLcp, kConfReq, lcp_req_id_, nullptr, 0);
}

void PppTerminator::SendIpcpConfReq() {
    /* Request only our gateway IP-Address (10.0.2.2). */
    uint8_t opt[6] = {kIpcpAddr, 6, kGwIp[0], kGwIp[1], kGwIp[2], kGwIp[3]};
    ipcp_req_id_ = next_id_++;
    SendCp(kProtoIpcp, kConfReq, ipcp_req_id_, opt, sizeof opt);
}

void PppTerminator::SendCp(uint16_t proto, uint8_t code, uint8_t id,
                           const uint8_t* data, size_t len) {
    std::vector<uint8_t> pkt;
    pkt.reserve(len + 4);
    pkt.push_back(code);
    pkt.push_back(id);
    Append16(pkt, (uint16_t)(len + 4));
    if (data && len) pkt.insert(pkt.end(), data, data + len);
    if (code != kEchoRep)
        LOG(Net, "[PPP] tx %s code=%u id=%u len=%zu\n",
            proto == kProtoLcp ? "LCP" : "IPCP", code, id, len);
    SendPpp(proto, pkt.data(), pkt.size());
}

void PppTerminator::SendPpp(uint16_t proto, const uint8_t* p, size_t len) {
    std::vector<uint8_t> out;
    hdlc_.BuildFrame(proto, p, len, out);
    rx_hold_.push_back(std::move(out));
    PumpLocked();
}

void PppTerminator::SetRts(bool on) {
    std::lock_guard<std::mutex> lk(mu_);
    rts_ = on;
    PumpLocked();
}

void PppTerminator::Pump() {
    std::lock_guard<std::mutex> lk(mu_);
    PumpLocked();
}

void PppTerminator::PumpLocked() {
    /* One frame in flight at a time: feed the next only when RTS is asserted and
       the guest has drained the UART, so its serial buffer is never flooded. */
    if (!rts_ || rx_hold_.empty() || !uart_.RxEmpty()) return;
    std::vector<uint8_t> f = std::move(rx_hold_.front());
    rx_hold_.erase(rx_hold_.begin());
    uart_.PushRx(f.data(), f.size());
}

/* ---- guest IP -> host (under mu_) ---- */

void PppTerminator::HandleGuestIp(const uint8_t* ip, size_t len) {
    if (!ipcp_open_ || len == 0) return;
    std::vector<uint8_t> eth;
    eth.reserve(len + kEthHeaderSize);
    AppendEthHeader(eth, gw_mac_.data(), guest_mac_.data(), kEthTypeIpv4);
    eth.insert(eth.end(), ip, ip + len);
    QueueTx(std::move(eth));
}

/* ---- host -> guest (slirp poll thread) ---- */

void PppTerminator::OnHostFrame(const uint8_t* eth, size_t len) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!active_ || len < kEthHeaderSize) return;
    const uint16_t type = EthType(eth);
    if (type == kEthTypeArp) { HandleArp(eth, len); return; }
    if (type != kEthTypeIpv4 || !ipcp_open_) return;
    SendPpp(kProtoIp, eth + kEthHeaderSize, len - kEthHeaderSize);
}

void PppTerminator::HandleArp(const uint8_t* eth, size_t len) {
    /* Answer ARP for the guest address on the guest's behalf (it has no L2),
       so libslirp's gateway can resolve 10.0.2.15 (RFC 826). */
    if (len < kEthHeaderSize + kArpPacketSize) return;
    const uint8_t* arp = eth + kEthHeaderSize;
    if (U16(arp, kArpOffOper) != kArpOperRequest) return;
    if (std::memcmp(arp + kArpOffTargetIp, kGuestIp, kIpv4AddrSize) != 0) return;

    const uint8_t* req_mac = arp + kArpOffSenderMac;
    const uint8_t* req_ip  = arp + kArpOffSenderIp;

    std::vector<uint8_t> out;
    out.reserve(kEthHeaderSize + kArpPacketSize);
    AppendArpFrame(out, req_mac, guest_mac_.data(), kArpOperReply, req_mac, req_ip);
    QueueTx(std::move(out));
}

void PppTerminator::QueueTx(std::vector<uint8_t> frame) {
    std::lock_guard<std::mutex> lk(out_mu_);
    outbound_.push_back(std::move(frame));
}

void PppTerminator::DrainTx() {
    std::vector<std::vector<uint8_t>> batch;
    {
        std::lock_guard<std::mutex> lk(out_mu_);
        if (outbound_.empty()) return;
        batch.swap(outbound_);
    }
    auto& net = emu_.Get<NetworkBackend>();
    for (auto& f : batch) net.SendFrame(f.data(), f.size());
}

void PppTerminator::BuildGratuitousArp(std::vector<uint8_t>& out) const {
    const uint8_t no_target_mac[kEthMacSize] = {};
    AppendArpFrame(out, gw_mac_.data(), guest_mac_.data(), kArpOperRequest,
                   no_target_mac, kGuestIp);
}
