#pragma once

#include "../core/byte_order.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace cerf::inet {

constexpr size_t   kEthMacSize      = 6;
constexpr size_t   kEthHeaderSize   = 14;
constexpr size_t   kEthMaxFrameSize = 1518;
constexpr size_t   kEthOffDst       = 0;
constexpr size_t   kEthOffSrc       = 6;
constexpr size_t   kEthOffType      = 12;
constexpr uint16_t kEthTypeIpv4     = 0x0800;
constexpr uint16_t kEthTypeArp      = 0x0806;
constexpr uint16_t kEthTypeIpv6     = 0x86DD;

constexpr size_t   kIpv4AddrSize    = 4;
constexpr size_t   kIpv4HeaderSize  = 20;
constexpr size_t   kIpOffProto      = 9;
constexpr size_t   kIpOffChecksum   = 10;
constexpr size_t   kIpOffSrc        = 12;
constexpr size_t   kIpOffDst        = 16;
constexpr uint8_t  kIpProtoIcmp     = 1;
constexpr uint8_t  kIpProtoTcp      = 6;
constexpr uint8_t  kIpProtoUdp      = 17;

constexpr size_t   kUdpHeaderSize   = 8;
constexpr size_t   kUdpOffSrcPort   = 0;
constexpr size_t   kUdpOffDstPort   = 2;
constexpr size_t   kUdpOffLen       = 4;
constexpr size_t   kUdpOffChecksum  = 6;
constexpr uint16_t kUdpPortDns      = 53;
constexpr uint16_t kUdpPortDhcpServer = 67;
constexpr uint16_t kUdpPortDhcpClient = 68;

constexpr size_t   kTcpHeaderSize   = 20;
constexpr size_t   kTcpOffSrcPort   = 0;
constexpr size_t   kTcpOffDstPort   = 2;
constexpr size_t   kTcpOffFlags     = 13;

constexpr size_t   kIcmpHeaderSize  = 8;
constexpr size_t   kIcmpOffType     = 0;
constexpr size_t   kIcmpOffCode     = 1;
constexpr size_t   kIcmpOffChecksum = 2;
constexpr size_t   kIcmpOffId       = 4;
constexpr size_t   kIcmpOffSeq      = 6;
constexpr uint8_t  kIcmpTypeEchoReply   = 0;
constexpr uint8_t  kIcmpTypeEchoRequest = 8;

constexpr size_t   kArpPacketSize   = 28;
constexpr size_t   kArpOffHtype     = 0;
constexpr size_t   kArpOffPtype     = 2;
constexpr size_t   kArpOffHlen      = 4;
constexpr size_t   kArpOffPlen      = 5;
constexpr size_t   kArpOffOper      = 6;
constexpr size_t   kArpOffSenderMac = 8;
constexpr size_t   kArpOffSenderIp  = 14;
constexpr size_t   kArpOffTargetMac = 18;
constexpr size_t   kArpOffTargetIp  = 24;

inline uint16_t EthType(const uint8_t* frame) { return be::U16(frame, kEthOffType); }
inline void PutEthType(uint8_t* frame, uint16_t type) { be::Put16(frame + kEthOffType, type); }
inline uint32_t Ipv4HeaderLen(const uint8_t* ip) { return (ip[0] & 0x0Fu) * 4u; }

inline void PutEthHeader(uint8_t* frame, const uint8_t* dst, const uint8_t* src, uint16_t type) {
    std::memcpy(frame + kEthOffDst, dst, kEthMacSize);
    std::memcpy(frame + kEthOffSrc, src, kEthMacSize);
    PutEthType(frame, type);
}

inline void AppendEthHeader(std::vector<uint8_t>& out, const uint8_t* dst, const uint8_t* src,
                            uint16_t type) {
    const size_t at = out.size();
    out.resize(at + kEthHeaderSize);
    PutEthHeader(out.data() + at, dst, src, type);
}

inline uint32_t WordSum(const uint8_t* data, size_t len, uint32_t seed = 0) {
    uint32_t sum = seed;
    for (size_t i = 0; i + 1 < len; i += 2) sum += be::U16(data, i);
    if (len & 1) sum += uint32_t(data[len - 1]) << 8;
    return sum;
}

inline uint16_t InetChecksum(const uint8_t* data, size_t len, uint32_t seed = 0) {
    uint32_t sum = WordSum(data, len, seed);
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return uint16_t(~sum);
}

inline void WriteIpv4Header(uint8_t* ip, uint16_t total_len, uint8_t proto,
                            const uint8_t* src_ip, const uint8_t* dst_ip) {
    ip[0] = 0x45;
    ip[1] = 0;
    be::Put16(ip + 2, total_len);
    be::Put16(ip + 4, 1);
    be::Put16(ip + 6, 0);
    ip[8] = 64;
    ip[kIpOffProto] = proto;
    be::Put16(ip + kIpOffChecksum, 0);
    std::memcpy(ip + kIpOffSrc, src_ip, kIpv4AddrSize);
    std::memcpy(ip + kIpOffDst, dst_ip, kIpv4AddrSize);
    be::Put16(ip + kIpOffChecksum, InetChecksum(ip, kIpv4HeaderSize));
}

}
