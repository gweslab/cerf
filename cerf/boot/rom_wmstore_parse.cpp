#include "rom_wmstore_parse.h"

#include "../core/byte_order.h"

#include <algorithm>
#include <cstring>
#include <string>

namespace cerf::rom_image_parse {

namespace {

using cerf::le::U16;
using cerf::le::U32;

struct EscoPayload {
    size_t off   = 0;
    size_t bytes = 0;
};

bool EscoPayloadSpan(std::span<const uint8_t> raw, EscoPayload& out) {
    if (raw.size() < kZipLocalHeaderSize ||
        std::memcmp(raw.data(), kEscoZipLocalSignature,
                    sizeof(kEscoZipLocalSignature)) != 0) {
        out = {0, raw.size()};
        return true;
    }
    const uint8_t* h = raw.data();
    if (U16(h, kZipMethodOff) != kZipMethodStore) return false;
    if ((U16(h, kZipFlagsOff) & kZipFlagDataDescriptor) != 0) return false;
    const uint32_t stored = U32(h, kZipCompressedSizeOff);
    if (stored != U32(h, kZipUncompressedSizeOff)) return false;
    const size_t off = kZipLocalHeaderSize
                     + size_t(U16(h, kZipNameLenOff))
                     + size_t(U16(h, kZipExtraLenOff));
    if (off >= raw.size() || uint64_t(off) + stored > raw.size()) return false;
    out = {off, stored};
    return true;
}

std::string PartitionName(const uint8_t* entry) {
    std::string name;
    for (size_t i = 0; i < kWmstorePartNameChars; ++i) {
        const uint16_t c = U16(entry, kWmstorePartNameOff + i * 2u);
        if (c == 0) break;
        if (c > 0x7Fu) return {};
        name.push_back(char(c));
    }
    return name;
}

}  /* namespace */

bool WmstoreLocateOsXip(std::span<const uint8_t> raw, WmstoreOsXip& out) {
    EscoPayload span;
    if (!EscoPayloadSpan(raw, span)) return false;
    const size_t payload     = span.off;
    const size_t payload_end = span.off + span.bytes;

    if (payload + kWmstoreSuperblockOff + sizeof(kWmstoreSignature) > payload_end)
        return false;
    if (std::memcmp(raw.data() + payload + kWmstoreSuperblockOff,
                    kWmstoreSignature, sizeof(kWmstoreSignature)) != 0)
        return false;

    for (size_t i = 0;; ++i) {
        const size_t entry_off =
            payload + kWmstorePartTableOff + i * kWmstorePartEntrySize;
        if (entry_off + kWmstorePartEntrySize > payload_end) break;

        const uint8_t* entry = raw.data() + entry_off;
        if (std::memcmp(entry, kWmpartSignature, sizeof(kWmpartSignature)) != 0)
            break;
        if (PartitionName(entry) != "NK") continue;

        const uint64_t start_off =
            uint64_t(payload)
            + uint64_t(U32(entry, kWmstorePartStartLbaOff)) * kWmstoreSectorBytes;
        const uint64_t part_bytes =
            uint64_t(U32(entry, kWmstorePartSizeLbaOff)) * kWmstoreSectorBytes;
        if (start_off > payload_end) return false;

        const size_t avail = size_t(std::min<uint64_t>(
            part_bytes, uint64_t(payload_end) - start_off));
        std::span<const uint8_t> xip = raw.subspan(size_t(start_off), avail);

        EcecRecord ecec;
        if (!ReadEcec(xip, kRomSignatureOffset, ecec)) return false;

        ParsedROMHDR hdr;
        if (!ParseSelfLocatingRomhdr(xip, ecec.ptoc, ecec.ptoc - ecec.romhdr_off, hdr))
            return false;
        if (hdr.physlast <= hdr.physfirst) return false;

        const uint32_t flat_size = hdr.physlast - hdr.physfirst;
        if (uint64_t(flat_size) > xip.size()) return false;

        out.data_off    = size_t(start_off);
        out.flat_size   = flat_size;
        out.base_va     = hdr.physfirst;
        out.payload_off   = payload;
        out.payload_bytes = span.bytes;
        return true;
    }
    return false;
}

}  /* namespace cerf::rom_image_parse */
