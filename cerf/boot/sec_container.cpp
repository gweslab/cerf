#include "sec_container.h"

#include "../core/byte_order.h"
#include "../storage/mapped_file.h"

#include <algorithm>

namespace {

constexpr uint32_t kSecMagic    = 0x400D400Du;
constexpr uint32_t kChunkHdrLen = 0x40u;

using cerf::le::U32;

}  /* namespace */

bool SecContainer::Open(MappedFile& mf) {
    valid_ = false;

    const uint8_t* h = mf.View(0, kChunkHdrLen);
    if (!h) return false;

    hdr_.magic        = U32(h, kSecOffMagic);
    hdr_.image_type   = U32(h, kSecOffImageType);
    hdr_.pkcs7_off    = U32(h, kSecOffPkcs7);
    hdr_.sgm_size     = U32(h, kSecOffSgmSize);
    hdr_.file_size    = U32(h, kSecOffFileSize);
    hdr_.cat_len      = U32(h, kSecOffCatLen);
    hdr_.payload_off  = U32(h, kSecOffPayload);
    hdr_.chunk_stride = U32(h, kSecOffChunkStride);
    hdr_.chunk_count  = U32(h, kSecOffChunkCount);

    if (hdr_.magic != kSecMagic)           return false;
    if (hdr_.chunk_stride <= kChunkHdrLen) return false;   /* data-per-chunk > 0 */
    if (hdr_.chunk_count == 0)             return false;

    /* The catalog at pkcs7_off is a PKCS#7 blob - an ASN.1 SEQUENCE (0x30 0x82). */
    const uint8_t* c = mf.View(hdr_.pkcs7_off, 2);
    if (!c || c[0] != 0x30 || c[1] != 0x82) return false;

    valid_ = true;
    return true;
}

uint64_t SecContainer::FlashSize(const MappedFile& mf) const {
    if (!valid_) return 0;
    const uint64_t data = static_cast<uint64_t>(hdr_.chunk_count)
                        * (hdr_.chunk_stride - kChunkHdrLen);
    return std::min<uint64_t>(data, mf.Size());
}

uint64_t SecContainer::FlashToFile(uint64_t flash_off) const {
    const uint64_t data_sz = hdr_.chunk_stride - kChunkHdrLen;
    return static_cast<uint64_t>(hdr_.payload_off)
         + (flash_off / data_sz) * hdr_.chunk_stride
         + kChunkHdrLen
         + (flash_off % data_sz);
}

size_t SecContainer::ReadFlash(MappedFile& mf, uint64_t flash_off,
                               void* dst, size_t len) const {
    if (!valid_) return 0;
    const uint64_t flash_size = FlashSize(mf);
    if (flash_off >= flash_size) return 0;
    len = static_cast<size_t>(std::min<uint64_t>(len, flash_size - flash_off));

    const uint64_t data_sz = hdr_.chunk_stride - kChunkHdrLen;
    auto*  out    = static_cast<uint8_t*>(dst);
    size_t copied = 0;
    while (copied < len) {
        const uint64_t cur    = flash_off + copied;
        const size_t   remain = static_cast<size_t>(
            std::min<uint64_t>(data_sz - (cur % data_sz), len - copied));
        const size_t got = mf.Read(FlashToFile(cur), out + copied, remain);
        if (got == 0) break;
        copied += got;
        if (got < remain) break;          /* end of file */
    }
    return copied;
}
