#include "rom_wmstore_parse.h"

#include "../core/byte_order.h"

#include <algorithm>
#include <cstring>
#include <string>

namespace cerf::rom_image_parse {

namespace {

using cerf::le::U16;
using cerf::le::U32;
using cerf::le::UN;

struct EscoPayload {
    size_t off   = 0;
    size_t bytes = 0;
};

bool LocalHeaderAt(std::span<const uint8_t> raw, size_t at) {
    return raw.size() - at >= sizeof(kEscoZipLocalSignature) &&
           std::memcmp(raw.data() + at, kEscoZipLocalSignature,
                       sizeof(kEscoZipLocalSignature)) == 0;
}

bool EscoStoredMemberAt(std::span<const uint8_t> raw, size_t at, EscoMember& out) {
    if (raw.size() - at < kZipLocalHeaderSize || !LocalHeaderAt(raw, at)) return false;
    const uint8_t* h = raw.data() + at;
    if (U16(h, kZipMethodOff) != kZipMethodStore) return false;
    if ((U16(h, kZipFlagsOff) & kZipFlagDataDescriptor) != 0) return false;
    const uint32_t stored = U32(h, kZipCompressedSizeOff);
    if (stored != U32(h, kZipUncompressedSizeOff)) return false;
    const size_t name_len = U16(h, kZipNameLenOff);
    const uint64_t data = uint64_t(at) + kZipLocalHeaderSize + name_len
                        + U16(h, kZipExtraLenOff);
    if (data >= raw.size() || data + stored > raw.size()) return false;
    out.name.assign(reinterpret_cast<const char*>(h + kZipLocalHeaderSize), name_len);
    out.off   = size_t(data);
    out.bytes = stored;
    return true;
}

bool EscoPayloadSpan(std::span<const uint8_t> raw, EscoPayload& out) {
    if (raw.size() < kZipLocalHeaderSize || !LocalHeaderAt(raw, 0)) {
        out = {0, raw.size()};
        return true;
    }
    EscoMember first;
    if (!EscoStoredMemberAt(raw, 0, first)) return false;
    out = {first.off, first.bytes};
    return true;
}

bool CertRange(std::span<const uint8_t> cert, uint32_t type, EscoRange& out) {
    if (cert.size() < kEscoCertBodyOff + kEscoCertRangeOff + kEscoCertRangeBytes)
        return false;
    const uint8_t* body = cert.data() + kEscoCertBodyOff;
    if (U32(body, kEscoCertRangeLenOff) != kEscoCertRangeBytes) return false;
    const uint8_t* rec = body + kEscoCertRangeOff;
    if (U32(rec) != type) return false;
    out.target = U32(rec, kEscoRangeTargetOff);
    out.drive  = U32(rec, kEscoRangeDriveOff);
    out.start = UN(rec + kEscoRangeStartOff, sizeof(uint64_t));
    out.size  = UN(rec + kEscoRangeSizeOff, sizeof(uint64_t));
    return out.size != 0u;
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

bool EscoStoredMembers(std::span<const uint8_t> raw, std::vector<EscoMember>& out) {
    out.clear();
    for (size_t at = 0; LocalHeaderAt(raw, at);) {
        EscoMember m;
        if (!EscoStoredMemberAt(raw, at, m)) return false;
        at = m.off + m.bytes;
        out.push_back(std::move(m));
    }
    return !out.empty();
}

bool EscoImageRange(std::span<const uint8_t> raw, EscoRange& out) {
    std::vector<EscoMember> members;
    if (!EscoStoredMembers(raw, members)) return false;
    const std::string cert_name = members[0].name + kEscoCertSuffix;
    for (const auto& m : members) {
        if (m.name != cert_name) continue;
        if (!CertRange(raw.subspan(m.off, m.bytes), kEscoRangeImageWrite, out))
            return false;
        return out.size == members[0].bytes;
    }
    return false;
}

bool EscoEraseRange(std::span<const uint8_t> raw, EscoRange& out) {
    std::vector<EscoMember> members;
    if (!EscoStoredMembers(raw, members) || members.size() != 1u) return false;
    const EscoMember& m = members[0];
    if (!m.name.ends_with(kEscoCertSuffix)) return false;
    return CertRange(raw.subspan(m.off, m.bytes), kEscoRangeErase, out);
}

}  /* namespace cerf::rom_image_parse */
