#pragma once

#include <cstdint>
#include <cstring>

namespace ford_sync2_media_hub_detail {

/* Original Ford A4 navigation card, read from its raw CID register by
   open-sync-maps tools/cid-reader/cid_reader.ino (2026-08-28): MID=28,
   OID="BE", PNM=five spaces, PRV=0.1, PSN=9C069B67, MDT=2014-03.
   The final B7 is CRC7 plus the mandatory end bit. */
inline void BuildA4Cid(uint8_t out[16]) {
    static constexpr uint8_t kA4Cid[16] = {
        0x28u, 0x42u, 0x45u, 0x20u, 0x20u, 0x20u, 0x20u, 0x20u,
        0x01u, 0x9Cu, 0x06u, 0x9Bu, 0x67u, 0x00u, 0xE3u, 0xB7u,
    };
    std::memcpy(out, kA4Cid, sizeof(kA4Cid));
}

}  // namespace ford_sync2_media_hub_detail
