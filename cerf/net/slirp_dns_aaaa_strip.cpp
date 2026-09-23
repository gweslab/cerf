#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "slirp_backend.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstring>
#include <mutex>
#include <vector>

#include "../core/byte_order.h"
#include "../core/log.h"
#include "ipv4_packet.h"

namespace {

using cerf::be::Put16;
using cerf::be::U16;
using namespace cerf::inet;

constexpr uint16_t QTYPE_AAAA = 28;
constexpr size_t   kDnsHeaderSize       = 12;
constexpr size_t   kDnsOffId            = 0;
constexpr size_t   kDnsOffFlags         = 2;
constexpr size_t   kDnsOffQdCount       = 4;
constexpr size_t   kDnsOffAnCount       = 6;
constexpr size_t   kDnsOffNsCount       = 8;
constexpr size_t   kDnsOffArCount       = 10;
constexpr size_t   kDnsQuestionTailSize = 4;
constexpr size_t   kDnsMinQuestionSize  = 1 + kDnsQuestionTailSize;

/* Walk DNS question name (labels + 00 terminator; compression not expected
   in a query). Returns offset just past the terminator, or 0 on malformed
   input. Caller must ensure `off` is inside `dns_len`. */
size_t SkipDnsName(const uint8_t* dns, size_t dns_len, size_t off) {
    while (off < dns_len) {
        uint8_t len = dns[off];
        if (len == 0) return off + 1;
        if ((len & 0xC0) != 0) return 0;  /* compression not allowed in question */
        off += (size_t)len + 1;
    }
    return 0;
}

/* Returns true if `frame` is a well-formed DNS query for QTYPE=AAAA and
   fills `*q_name_end_off` with the offset into the DNS payload just past
   the question name's null terminator (i.e. the start of QTYPE/QCLASS). */
bool IsAaaaQuery(const uint8_t* frame, size_t len, size_t* dns_off_out,
                 size_t* dns_len_out, size_t* q_name_end_off_out) {
    if (len < kEthHeaderSize + kIpv4HeaderSize + kUdpHeaderSize + kDnsHeaderSize + kDnsMinQuestionSize)
        return false;
    if (EthType(frame) != kEthTypeIpv4) return false;

    const uint8_t* ip = frame + kEthHeaderSize;
    if ((ip[0] & 0xF0) != 0x40) return false;
    const uint32_t ihl = Ipv4HeaderLen(ip);
    if (ihl < kIpv4HeaderSize) return false;
    if (ip[kIpOffProto] != kIpProtoUdp) return false;

    size_t udp_off = kEthHeaderSize + ihl;
    if (udp_off + kUdpHeaderSize > len) return false;
    const uint8_t* udp = frame + udp_off;
    uint16_t dst_port = U16(udp, kUdpOffDstPort);
    if (dst_port != kUdpPortDns) return false;

    uint16_t udp_len_field = U16(udp, kUdpOffLen);
    if (udp_len_field < kUdpHeaderSize) return false;
    size_t dns_off = udp_off + kUdpHeaderSize;
    size_t dns_len = (size_t)udp_len_field - kUdpHeaderSize;
    if (dns_off + dns_len > len) return false;
    if (dns_len < kDnsHeaderSize + kDnsMinQuestionSize) return false;

    const uint8_t* dns = frame + dns_off;
    uint16_t flags    = U16(dns, kDnsOffFlags);
    if (flags & 0x8000) return false;
    uint16_t qd_count = U16(dns, kDnsOffQdCount);
    if (qd_count != 1) return false;

    size_t name_end = SkipDnsName(dns, dns_len, kDnsHeaderSize);
    if (name_end == 0 || name_end + kDnsQuestionTailSize > dns_len) return false;

    uint16_t qtype  = U16(dns, name_end);
    if (qtype != QTYPE_AAAA) return false;

    *dns_off_out        = dns_off;
    *dns_len_out        = dns_len;
    *q_name_end_off_out = name_end;
    return true;
}

/* Build a NoData response frame from the query frame. The response
   echoes the question section verbatim, sets QR=1/AA=0/RA=1/RCODE=0
   (NoError, NoData), and ANCOUNT=NSCOUNT=ARCOUNT=0. Swaps src/dst MAC,
   IP, and UDP port; recomputes IPv4 and UDP checksums. */
std::vector<uint8_t> BuildAaaaNoDataReply(const uint8_t* query_frame,
                                          size_t query_len,
                                          size_t dns_off,
                                          size_t q_name_end) {
    size_t resp_dns_len = q_name_end + kDnsQuestionTailSize;
    if (dns_off + resp_dns_len > query_len) return {};

    size_t resp_udp_len = kUdpHeaderSize + resp_dns_len;
    size_t resp_ip_len  = kIpv4HeaderSize + resp_udp_len;
    size_t resp_total   = kEthHeaderSize + resp_ip_len;

    std::vector<uint8_t> out(resp_total, 0);

    PutEthHeader(out.data(), query_frame + kEthOffSrc, query_frame + kEthOffDst, kEthTypeIpv4);

    uint8_t* oip = out.data() + kEthHeaderSize;
    const uint8_t* qip = query_frame + kEthHeaderSize;
    const uint32_t qihl = Ipv4HeaderLen(qip);
    WriteIpv4Header(oip, static_cast<uint16_t>(resp_ip_len), kIpProtoUdp,
                    qip + kIpOffDst, qip + kIpOffSrc);

    uint8_t* oudp = out.data() + kEthHeaderSize + kIpv4HeaderSize;
    const uint8_t* qudp = query_frame + kEthHeaderSize + qihl;
    std::memcpy(oudp + kUdpOffSrcPort, qudp + kUdpOffDstPort, 2);
    std::memcpy(oudp + kUdpOffDstPort, qudp + kUdpOffSrcPort, 2);
    Put16(oudp + kUdpOffLen, static_cast<uint16_t>(resp_udp_len));
    Put16(oudp + kUdpOffChecksum, 0);

    uint8_t* odns = out.data() + kEthHeaderSize + kIpv4HeaderSize + kUdpHeaderSize;
    const uint8_t* qdns = query_frame + dns_off;
    std::memcpy(odns + kDnsOffId, qdns + kDnsOffId, 2);
    uint8_t rd = (uint8_t)(qdns[kDnsOffFlags] & 0x01);
    odns[kDnsOffFlags]     = (uint8_t)(0x80 | rd);
    odns[kDnsOffFlags + 1] = (uint8_t)(0x80);
    Put16(odns + kDnsOffQdCount, 1);
    Put16(odns + kDnsOffAnCount, 0);
    Put16(odns + kDnsOffNsCount, 0);
    Put16(odns + kDnsOffArCount, 0);

    std::memcpy(odns + kDnsHeaderSize, qdns + kDnsHeaderSize, resp_dns_len - kDnsHeaderSize);

    uint8_t pseudo[12] = {};
    std::memcpy(pseudo + 0, oip + kIpOffSrc, kIpv4AddrSize);
    std::memcpy(pseudo + 4, oip + kIpOffDst, kIpv4AddrSize);
    pseudo[8]  = 0;
    pseudo[9]  = kIpProtoUdp;
    Put16(pseudo + 10, static_cast<uint16_t>(resp_udp_len));
    uint16_t udp_ck = InetChecksum(oudp, resp_udp_len, WordSum(pseudo, sizeof(pseudo)));
    if (udp_ck == 0) udp_ck = 0xFFFF;
    Put16(oudp + kUdpOffChecksum, udp_ck);

    return out;
}

} /* namespace */

bool SlirpBackend::TryInterceptAaaaQuery(const uint8_t* frame, std::size_t len) {
    if (host_has_v6_) return false;                              /* IPv6 works - let AAAA through */

    size_t dns_off = 0, dns_len = 0, q_name_end = 0;
    if (!IsAaaaQuery(frame, len, &dns_off, &dns_len, &q_name_end)) return false;

    std::vector<uint8_t> reply =
        BuildAaaaNoDataReply(frame, len, dns_off, q_name_end);
    if (reply.empty()) return false;

    DispatchFrame(reply.data(), reply.size());

    LOG(Net, "AAAA NoData synthesized (host has no v6 internet; "
             "%u-byte query → %zu-byte reply)\n",
        (unsigned)len, reply.size());
    return true;
}
