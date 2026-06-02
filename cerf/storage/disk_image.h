#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstdint>
#include <string>

/* File-backed emulated disk, one value per attached drive (not a singleton).
   `size` is the logical capacity reported to the guest; the file grows on write
   (never pre-extended), so a blank image costs ~0 host disk. */
class DiskImage {
public:
    DiskImage() = default;
    ~DiskImage();
    DiskImage(const DiskImage&)            = delete;
    DiskImage& operator=(const DiskImage&) = delete;

    static constexpr uint32_t kSectorSize = 512u;

    bool Open(const std::string& path, uint64_t size_bytes);

    bool     IsOpen()      const { return handle_ != INVALID_HANDLE_VALUE; }
    uint64_t SectorCount() const { return sector_count_; }

    /* 512-byte LBA I/O; false on out-of-range or host error so the caller
       raises ATA ERR rather than fabricating data. */
    bool ReadSectors (uint64_t lba, uint32_t count, void*       dst);
    bool WriteSectors(uint64_t lba, uint32_t count, const void* src);

private:
    bool SeekTo(uint64_t lba);

    HANDLE   handle_       = INVALID_HANDLE_VALUE;
    uint64_t sector_count_ = 0;
};
