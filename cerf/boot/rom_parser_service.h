#pragma once

#include "../core/service.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

/* TOCentry — 32 bytes per romldr.h. Fields named verbatim from the
   original C struct; `lpszFileName` carries the resolved ASCII name
   rather than the in-ROM LPSTR VA. `ftTime` is the 64-bit FILETIME
   value (low | high<<32). */
struct ParsedTOCentry {
    uint32_t    dwFileAttributes = 0;
    uint64_t    ftTime           = 0;
    uint32_t    nFileSize        = 0;
    std::string lpszFileName;
    uint32_t    ulE32Offset      = 0;
    uint32_t    ulO32Offset      = 0;
    uint32_t    ulLoadOffset     = 0;
};

/* FILESentry — 28 bytes per romldr.h. */
struct ParsedFILESentry {
    uint32_t    dwFileAttributes = 0;
    uint64_t    ftTime           = 0;
    uint32_t    nRealFileSize    = 0;
    uint32_t    nCompFileSize    = 0;
    std::string lpszFileName;
    uint32_t    ulLoadOffset     = 0;
};

/* ROMHDR — 84 bytes per romldr.h. Field names match the C struct
   exactly. `pExtensions` is a 32-bit kernel-VA in the ROM, not a host
   pointer. The kernel's baked pTOC slot is set by romimage to the
   kernel-VA of this struct. */
struct ParsedROMHDR {
    uint32_t dllfirst        = 0;
    uint32_t dlllast         = 0;
    uint32_t physfirst       = 0;
    uint32_t physlast        = 0;
    uint32_t nummods         = 0;
    uint32_t ulRAMStart      = 0;
    uint32_t ulRAMFree       = 0;
    uint32_t ulRAMEnd        = 0;
    uint32_t ulCopyEntries   = 0;
    uint32_t ulCopyOffset    = 0;
    uint32_t ulProfileLen    = 0;
    uint32_t ulProfileOffset = 0;
    uint32_t numfiles        = 0;
    uint32_t ulKernelFlags   = 0;
    uint32_t ulFSRamPercent  = 0;
    uint32_t ulDrivglobStart = 0;
    uint32_t ulDrivglobLen   = 0;
    uint16_t usCPUType       = 0;
    uint16_t usMiscFlags     = 0;
    uint32_t pExtensions     = 0;
    uint32_t ulTrackingStart = 0;
    uint32_t ulTrackingLen   = 0;
};

/* ParsedTOC — what the kernel sees at one pTOC slot: a ROMHDR
   followed by `romhdr.nummods` TOCentry records, then
   `romhdr.numfiles` FILESentry records. `romhdr_va` is the kernel-VA
   romimage burned into the kernel binary's pTOC slot. */
struct ParsedTOC {
    uint32_t                       romhdr_va = 0;
    ParsedROMHDR                   romhdr;
    std::vector<ParsedTOCentry>    modules;
    std::vector<ParsedFILESentry>  files;
};

/* `load_offset` is the kernel-VA that file offset 0 of THIS XIP
   region's address space corresponds to (file offset = kernel-VA
   - load_offset). Different XIP regions in the same NB0 have
   different load_offsets. */
struct ParsedXipRegion {
    uint32_t   load_offset = 0;
    ParsedTOC  toc;
};

struct ParsedImgfsModule {
    std::string lpszFileName;
    size_t      dirent_file_off = 0;
    uint32_t    file_size       = 0;
    uint32_t    mod_indexptr    = 0;
    uint32_t    mod_indexsize   = 0;
    struct Section {
        std::string name;
        size_t      dirent_file_off = 0;
        uint32_t    file_size       = 0;
        uint32_t    sec_indexptr    = 0;
        uint32_t    sec_indexsize   = 0;
    };
    std::vector<Section> sections;
};

struct ParsedRom {
    std::string                  filename;       /* e.g. "NK.bin"      */
    std::string                  path;           /* absolute on disk   */
    std::vector<uint8_t>         raw;            /* file bytes         */
    std::vector<uint8_t>         flat_storage;   /* B000FF assembly    */
    std::span<const uint8_t>     flat;           /* span over storage  */
    uint32_t                     flat_base_va = 0;
    uint32_t                     entry_va     = 0;
    bool                         is_b000ff    = false;
    bool                         has_imgfs        = false;
    bool                         imgfs_is_ftl     = false;
    uint32_t                     imgfs_file_off   = 0;
    uint32_t                     imgfs_bytes_per_block = 0;
    std::vector<ParsedXipRegion> xips;
    std::vector<ParsedImgfsModule> imgfs_modules;
};

class RomParserService : public Service {
public:
    using Service::Service;
    void OnReady() override;

    /* True once every declared partition parsed successfully. */
    bool Ok() const { return ok_; }

    /* Primary partition (loaded_[0]). The one whose entry_va boots. */
    const ParsedRom& Primary() const { return loaded_[0]; }

    /* All partitions placed in DRAM (primary at [0], extensions
       after). Excludes the recovery partition, which is declared in
       cerf.json but not loaded today. */
    const std::vector<ParsedRom>& Loaded() const { return loaded_; }

    /* Shortcut for the primary partition's entry kernel-VA. */
    uint32_t EntryVa() const { return loaded_[0].entry_va; }

    /* The primary partition's kernel module (nk.exe). Null if absent. */
    const ParsedTOCentry* KernelModule() const;

    /* Slice of bytes covering kernel-VA [va, va+len), searching every
       loaded partition. Empty span if no partition's flat range covers
       the request. */
    std::span<const uint8_t> ReadVa(uint32_t va, uint32_t len) const;

    /* Bytes of a module by name (case-insensitive), searching every
       loaded partition's TOC. Returns the e32_rom.vsize-sized span
       starting at the module's ulLoadOffset; empty when not found. */
    std::span<const uint8_t> ModuleBytesByName(const char* name) const;

private:
    bool ParseOne(ParsedRom& rom);

    bool                   ok_ = false;
    std::vector<ParsedRom> loaded_;
};
