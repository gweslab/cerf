#include "pe_image.h"

#include "../core/log.h"

#include <cstring>

namespace {

constexpr uint16_t kDosMagic       = 0x5A4D;       /* 'MZ' */
constexpr uint32_t kPeSignature    = 0x00004550;   /* 'PE\0\0' */
constexpr uint16_t kOptHdrMagicPe32 = 0x010B;
constexpr int      kNumberOfDirs   = 16;
constexpr size_t   kSecHdrSize     = 40;

constexpr size_t kOptOffMagic            = 0;
constexpr size_t kOptOffEntryPoint       = 16;
constexpr size_t kOptOffImageBase        = 28;
constexpr size_t kOptOffMajorSubsys      = 48;
constexpr size_t kOptOffMinorSubsys      = 50;
constexpr size_t kOptOffSizeOfImage      = 56;
constexpr size_t kOptOffSubsystem        = 68;
constexpr size_t kOptOffStackReserve     = 72;
constexpr size_t kOptOffNumberOfRvaAndSizes = 92;
constexpr size_t kOptOffDataDirectory    = 96;

/* IMAGE_FILE_HEADER field offsets within the NT-headers struct (i.e.
   starting from the 'PE\0\0' signature + 4). */
constexpr size_t kFileOffNumberOfSections   = 2;
constexpr size_t kFileOffSizeOfOptionalHdr  = 16;
constexpr size_t kFileOffCharacteristics    = 18;

/* IMAGE_SECTION_HEADER field offsets. */
constexpr size_t kSecOffVirtualSize         = 8;
constexpr size_t kSecOffVirtualAddress      = 12;
constexpr size_t kSecOffSizeOfRawData       = 16;
constexpr size_t kSecOffPointerToRawData    = 20;
constexpr size_t kSecOffCharacteristics     = 36;

uint16_t RdU16(const uint8_t* p, size_t off) {
    return uint16_t(p[off]) | (uint16_t(p[off + 1]) << 8);
}
uint32_t RdU32(const uint8_t* p, size_t off) {
    return uint32_t(p[off])
         | (uint32_t(p[off + 1]) << 8)
         | (uint32_t(p[off + 2]) << 16)
         | (uint32_t(p[off + 3]) << 24);
}

}  /* namespace */

PeImage::PeImage(std::vector<uint8_t> pe_bytes)
    : pe_bytes_(std::move(pe_bytes))
{
    if (pe_bytes_.size() < 0x40) {
        LOG(Caution, "[PeImage] DOS header too small (%zu bytes)\n", pe_bytes_.size());
        return;
    }
    if (RdU16(pe_bytes_.data(), 0) != kDosMagic) {
        LOG(Caution, "[PeImage] bad DOS magic\n");
        return;
    }
    const uint32_t e_lfanew = RdU32(pe_bytes_.data(), 0x3C);
    if (e_lfanew + 24 + 224 > pe_bytes_.size()) {
        LOG(Caution, "[PeImage] PE header offset out of bounds: 0x%X\n", e_lfanew);
        return;
    }
    if (RdU32(pe_bytes_.data(), e_lfanew) != kPeSignature) {
        LOG(Caution, "[PeImage] bad PE signature\n");
        return;
    }

    const size_t file_hdr_off    = e_lfanew + 4;
    machine_                     = RdU16(pe_bytes_.data(), file_hdr_off + 0);
    const uint16_t num_sections  = RdU16(pe_bytes_.data(), file_hdr_off + kFileOffNumberOfSections);
    const uint16_t opt_hdr_size  = RdU16(pe_bytes_.data(), file_hdr_off + kFileOffSizeOfOptionalHdr);
    image_flags_                 = RdU16(pe_bytes_.data(), file_hdr_off + kFileOffCharacteristics);

    const size_t opt_hdr_off = file_hdr_off + 20;
    const uint16_t magic = RdU16(pe_bytes_.data(), opt_hdr_off + kOptOffMagic);
    if (magic != kOptHdrMagicPe32) {
        LOG(Caution, "[PeImage] not PE32 (optional-header magic=0x%X)\n", magic);
        return;
    }

    entry_rva_      = RdU32(pe_bytes_.data(), opt_hdr_off + kOptOffEntryPoint);
    image_base_     = RdU32(pe_bytes_.data(), opt_hdr_off + kOptOffImageBase);
    image_size_     = RdU32(pe_bytes_.data(), opt_hdr_off + kOptOffSizeOfImage);
    subsystem_      = RdU16(pe_bytes_.data(), opt_hdr_off + kOptOffSubsystem);
    stack_reserve_  = RdU32(pe_bytes_.data(), opt_hdr_off + kOptOffStackReserve);
    subsys_major_   = RdU16(pe_bytes_.data(), opt_hdr_off + kOptOffMajorSubsys);
    subsys_minor_   = RdU16(pe_bytes_.data(), opt_hdr_off + kOptOffMinorSubsys);

    /* PE images can declare fewer than 16 data directories
       (NumberOfRvaAndSizes < 16); entries past that count must be
       treated as zero rather than read from random bytes following
       the section table. */
    const uint32_t num_dirs_in_pe = RdU32(pe_bytes_.data(), opt_hdr_off + kOptOffNumberOfRvaAndSizes);
    const uint32_t copy_dirs =
        num_dirs_in_pe < uint32_t(kNumberOfDirs) ? num_dirs_in_pe : uint32_t(kNumberOfDirs);
    const size_t dirs_off = opt_hdr_off + kOptOffDataDirectory;
    for (uint32_t i = 0; i < copy_dirs; ++i) {
        dirs_[i].rva  = RdU32(pe_bytes_.data(), dirs_off + i * 8);
        dirs_[i].size = RdU32(pe_bytes_.data(), dirs_off + i * 8 + 4);
    }

    const size_t sec_off = opt_hdr_off + opt_hdr_size;
    if (sec_off + size_t(num_sections) * kSecHdrSize > pe_bytes_.size()) {
        LOG(Caution, "[PeImage] section table out of bounds: "
                "sec_off=0x%zX num=%u file=%zu\n",
            sec_off, (unsigned)num_sections, pe_bytes_.size());
        return;
    }
    sections_.reserve(num_sections);
    for (uint16_t i = 0; i < num_sections; ++i) {
        const size_t s = sec_off + size_t(i) * kSecHdrSize;
        Section sec;
        sec.vsize       = RdU32(pe_bytes_.data(), s + kSecOffVirtualSize);
        sec.rva         = RdU32(pe_bytes_.data(), s + kSecOffVirtualAddress);
        sec.psize       = RdU32(pe_bytes_.data(), s + kSecOffSizeOfRawData);
        sec.pe_file_off = RdU32(pe_bytes_.data(), s + kSecOffPointerToRawData);
        sec.flags       = RdU32(pe_bytes_.data(), s + kSecOffCharacteristics);
        sections_.push_back(sec);
    }

    parsed_ = true;
    LOG(Boot, "[PeImage] parsed: entry_rva=0x%X image_base=0x%X "
              "image_size=0x%X subsys=%u sections=%u\n",
        entry_rva_, image_base_, image_size_, (unsigned)subsystem_, (unsigned)num_sections);
}
