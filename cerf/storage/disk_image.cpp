#include "disk_image.h"

#include <winioctl.h>  /* FSCTL_SET_SPARSE (excluded by WIN32_LEAN_AND_MEAN) */
#include <cstring>

#include "../core/log.h"

DiskImage::~DiskImage() {
    if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
}

bool DiskImage::Open(const std::string& path, uint64_t size_bytes) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        LOG(Caution, "DiskImage: CreateFile('%s') failed gle=%lu\n",
            path.c_str(), GetLastError());
        return false;
    }

    /* Do NOT pre-extend to size_bytes: filesystems that ignore FSCTL_SET_SPARSE
       (e.g. vboxsf) would allocate the whole capacity, making a blank disk a
       30 GB file. size_bytes is logical only; the file grows on write and reads
       past the physical end return zero (ReadSectors). */
    DWORD junk = 0;
    DeviceIoControl(h, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &junk, nullptr);

    handle_ = h;
    /* Advertise max(logical, physical): if IDENTIFY reports fewer sectors than
       a real dump's MBR partitions span, mspart rejects the table and nothing
       mounts. max() keeps a blank allocate-on-write disk at logical capacity. */
    LARGE_INTEGER phys{};
    const uint64_t physical = GetFileSizeEx(h, &phys)
                                  ? static_cast<uint64_t>(phys.QuadPart) : 0u;
    const uint64_t advertised = physical > size_bytes ? physical : size_bytes;
    sector_count_ = advertised / kSectorSize;
    LOG(Boot, "DiskImage: '%s' open, %llu sectors (%llu MB; logical %llu MB, "
              "physical %llu MB)\n",
        path.c_str(), static_cast<unsigned long long>(sector_count_),
        static_cast<unsigned long long>(advertised / (1024u * 1024u)),
        static_cast<unsigned long long>(size_bytes / (1024u * 1024u)),
        static_cast<unsigned long long>(physical / (1024u * 1024u)));
    return true;
}

bool DiskImage::SeekTo(uint64_t lba) {
    LARGE_INTEGER off;
    off.QuadPart = static_cast<LONGLONG>(lba * kSectorSize);
    return SetFilePointerEx(handle_, off, nullptr, FILE_BEGIN) != 0;
}

bool DiskImage::ReadSectors(uint64_t lba, uint32_t count, void* dst) {
    if (handle_ == INVALID_HANDLE_VALUE || lba + count > sector_count_) return false;
    const uint64_t off  = lba * kSectorSize;
    const DWORD    want = count * kSectorSize;
    auto* out = static_cast<uint8_t*>(dst);

    /* The file grows on write and is shorter than the logical capacity, so any
       range at/after the physical end is unwritten — return zero for it. */
    LARGE_INTEGER phys{};
    if (!GetFileSizeEx(handle_, &phys)) return false;
    const uint64_t psize = static_cast<uint64_t>(phys.QuadPart);
    if (off >= psize) { std::memset(out, 0, want); return true; }

    const uint64_t avail   = psize - off;
    const DWORD    in_file = (avail >= want) ? want : static_cast<DWORD>(avail);
    if (!SeekTo(lba)) return false;
    DWORD got = 0;
    if (!ReadFile(handle_, out, in_file, &got, nullptr) || got != in_file) return false;
    if (in_file < want) std::memset(out + in_file, 0, want - in_file);
    return true;
}

bool DiskImage::WriteSectors(uint64_t lba, uint32_t count, const void* src) {
    if (handle_ == INVALID_HANDLE_VALUE || lba + count > sector_count_) return false;
    if (!SeekTo(lba)) return false;
    const DWORD want = count * kSectorSize;
    DWORD put = 0;
    return WriteFile(handle_, src, want, &put, nullptr) && put == want;
}
