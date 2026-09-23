#pragma once

#include <cstddef>
#include <cstdint>

class MappedFile;

/* Header of a Ford `.sec` update package (little-endian, first 0x40 bytes).
   Field offsets reverse-engineered + validated against the device `.sec`. */
constexpr uint32_t kSecOffMagic       = 0x00;
constexpr uint32_t kSecOffImageType   = 0x08;
constexpr uint32_t kSecOffPkcs7       = 0x0C;
constexpr uint32_t kSecOffSgmSize     = 0x14;
constexpr uint32_t kSecOffFileSize    = 0x18;
constexpr uint32_t kSecOffCatLen      = 0x20;
constexpr uint32_t kSecOffPayload     = 0x24;
constexpr uint32_t kSecOffChunkStride = 0x28;
constexpr uint32_t kSecOffChunkCount  = 0x2C;

struct SecHeader {
    uint32_t magic;
    uint32_t image_type;
    uint32_t pkcs7_off;
    uint32_t sgm_size;
    uint32_t file_size;
    uint32_t cat_len;
    uint32_t payload_off;
    uint32_t chunk_stride;
    uint32_t chunk_count;
};

/* Reads the device's NAND flash, de-chunked from a `.sec`. The caller owns the
   MappedFile passed to each read (the 1.96 GiB file is never mapped whole). */
class SecContainer {
public:
    /* Parse + validate `mf`; returns false and stays invalid if `mf` isn't a `.sec`. */
    bool Open(MappedFile& mf);

    bool             IsValid() const { return valid_; }
    const SecHeader& Header()  const { return hdr_; }

    /* Total de-chunked flash size in bytes (chunk_count * data-per-chunk). */
    uint64_t FlashSize(const MappedFile& mf) const;

    /* Byte offset within the `.sec` file holding the flash byte at `flash_off`. */
    uint64_t FlashToFile(uint64_t flash_off) const;

    /* Copy `len` flash bytes at `flash_off` into `dst`, walking chunk
       boundaries (a single MappedFile read never crosses a 0x40 chunk header).
       Returns bytes copied (< len at end of flash). */
    size_t ReadFlash(MappedFile& mf, uint64_t flash_off, void* dst, size_t len) const;

private:
    SecHeader hdr_   {};
    bool      valid_ = false;
};
