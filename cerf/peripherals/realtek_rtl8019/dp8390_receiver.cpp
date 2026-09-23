#include "dp8390_receiver.h"

#include "../../core/byte_order.h"
#include "../../core/log.h"
#include "../../net/ipv4_packet.h"

#include <cstring>

using namespace dp8390;

namespace {

/* DP8390D datasheet, 1992 National LAN databook, MAR0-MAR7 p. 1-158. */
uint32_t MulticastFilterBit(const uint8_t* dest) {
    uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < cerf::inet::kEthMacSize; ++i) {
        uint8_t octet = dest[i];
        for (int bit = 0; bit < 8; ++bit) {
            const uint32_t feed = ((crc >> 31) ^ octet) & 0x1u;
            crc <<= 1;
            octet >>= 1;
            if (feed != 0u) crc ^= kAutodinIIPoly;
        }
    }
    return crc >> 26;
}

}

Dp8390Receiver::Dp8390Receiver(Dp8390& nic,
                               std::array<uint8_t, Dp8390::kRamSize>& ram)
    : nic_(nic), ram_(ram) {}

bool Dp8390Receiver::AcceptsDestinationLocked(const uint8_t* dest) const {
    /* DP8390D datasheet, 1992 National LAN databook, destination address
       p. 1-133, RCR p. 1-155, MAR0-MAR7 p. 1-158. */
    bool all_ones = true;
    for (std::size_t i = 0; i < cerf::inet::kEthMacSize; ++i) {
        if (dest[i] != 0xFFu) {
            all_ones = false;
            break;
        }
    }
    if (all_ones) {
        return (nic_.rcr_ & kRcrBroadcast) != 0u;
    }

    if ((dest[0] & 0x01u) != 0u) {
        if (!(nic_.rcr_ & kRcrMulticast)) return false;
        const uint32_t filter_bit = MulticastFilterBit(dest);
        return (nic_.mar_[filter_bit >> 3] &
                (1u << (filter_bit & 0x7u))) != 0u;
    }

    if (nic_.rcr_ & kRcrPromiscuous) return true;
    return std::memcmp(dest, nic_.par_.data(), nic_.par_.size()) == 0;
}

bool Dp8390Receiver::OnFrameLocked(const uint8_t* frame, std::size_t len) {
    /* DP8390D datasheet, 1992 National LAN databook, 11.0 p. 1-159: "The
       NIC remains in its reset state until a Start Command is issued.
       This guarantees that no packets are transmitted or received". */
    if (nic_.cr_ & kCrStp) return false;
    /* DP8390D datasheet, 1992 National LAN databook, DCR.LS p. 1-152:
       "0: Loopback mode selected". */
    if (!(nic_.dcr_ & kDcrLoopbackSelect)) return false;
    if (nic_.tcr_ & kTcrLoopbackBits) return false;

    if (!AcceptsDestinationLocked(frame)) return false;

    /* DP8390D datasheet, 1992 National LAN databook, CNTR2 p. 1-159:
       "In monitor mode, this counter will count the number of packets
       that pass the address recognition logic"; RSR.MPA p. 1-156. */
    if (nic_.rcr_ & kRcrMonitor) {
        nic_.rsr_ |= kRsrMpa;
        nic_.BumpCntr2Locked();
        return false;
    }

    const uint8_t kPageMin = Dp8390::kRamBase >> 8;
    const uint8_t kPageMax = (Dp8390::kRamBase + Dp8390::kRamSize) >> 8;
    if (nic_.pstart_ < kPageMin || nic_.pstart_ >= kPageMax ||
        nic_.pstop_  < kPageMin || nic_.pstop_  >  kPageMax ||
        nic_.pstart_ >= nic_.pstop_ ||
        nic_.curr_   < nic_.pstart_ || nic_.curr_ >= nic_.pstop_) {
        LOG(Caution, "[NE2000] RX with inconsistent ring geometry "
                "PSTART=0x%02X PSTOP=0x%02X CURR=0x%02X; halting\n",
            nic_.pstart_, nic_.pstop_, nic_.curr_);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    /* DP8390D datasheet, 1992 National LAN databook, storage format
       p. 1-141: status, next packet pointer, byte count 0, byte count 1,
       then data; p. 1-138: 4-byte offset reserved for receive status. */
    const uint32_t total_with_header = static_cast<uint32_t>(len) + 4u;
    const uint8_t  pages_used =
        static_cast<uint8_t>((total_with_header + 0xFFu) >> 8);
    /* DP8390D datasheet, 1992 National LAN databook, p. 1-138: buffers
       cannot be skipped when linking, and a local DMA address reaching
       the Boundary aborts reception - a packet larger than the ring
       reaches it unconditionally. */
    if (pages_used >= static_cast<uint8_t>(nic_.pstop_ - nic_.pstart_)) {
        nic_.rsr_ |= kRsrMpa;
        nic_.BumpCntr2Locked();
        nic_.rst_overflow_ = true;
        nic_.RaiseIsrLocked(kIsrOvw | kIsrRst);
        return false;
    }
    uint8_t next_page = static_cast<uint8_t>(nic_.curr_ + pages_used);
    if (next_page >= nic_.pstop_) {
        next_page = static_cast<uint8_t>(
            nic_.pstart_ + (next_page - nic_.pstop_));
    }

    /* DP8390D datasheet, 1992 National LAN databook, p. 1-138: before
       the next buffer is linked its address is compared to the Boundary
       Pointer; equality aborts reception. p. 1-150: RST "is also set
       when a Receive Buffer Ring overflow occurs". */
    uint8_t link = nic_.curr_;
    for (uint8_t i = 1u; i < pages_used; ++i) {
        link = static_cast<uint8_t>(link + 1u);
        if (link >= nic_.pstop_) link = nic_.pstart_;
        if (link != nic_.bnry_) continue;
        nic_.rsr_ |= kRsrMpa;
        nic_.BumpCntr2Locked();
        nic_.rst_overflow_ = true;
        nic_.RaiseIsrLocked(kIsrOvw | kIsrRst);
        return false;
    }

    const uint32_t start_off =
        (uint32_t)nic_.curr_ * 256u - Dp8390::kRamBase;
    const uint32_t stop_off  =
        (uint32_t)nic_.pstop_ * 256u - Dp8390::kRamBase;

    auto write_into_ring = [&](uint32_t off, const uint8_t* src,
                               std::size_t n) {
        const uint32_t first = (off + n <= stop_off)
                               ? static_cast<uint32_t>(n)
                               : (stop_off - off);
        std::memcpy(ram_.data() + off, src, first);
        if (first < n) {
            const uint32_t wrap_off =
                (uint32_t)nic_.pstart_ * 256u - Dp8390::kRamBase;
            std::memcpy(ram_.data() + wrap_off, src + first, n - first);
        }
    };

    const uint8_t status = static_cast<uint8_t>(
        kRsrPrx | ((frame[cerf::inet::kEthOffDst] & 0x01u) ? kRsrPhy : 0u));
    uint8_t header[4] = {status, next_page};
    cerf::le::Put16(header + 2, static_cast<uint16_t>(total_with_header));
    write_into_ring(start_off, header, 4);
    write_into_ring(start_off + 4u, frame, len);

    nic_.curr_ = next_page;
    nic_.rsr_  = status;
    nic_.RaiseIsrLocked(kIsrPrx);
    return true;
}
