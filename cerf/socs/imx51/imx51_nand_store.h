#pragma once

#include "../../core/service.h"
#include "../../host/host_widget.h"
#include "../../storage/disk_image.h"

#include <array>
#include <cstdint>
#include <string>
#include <unordered_map>

class Imx51NandStore : public Service, public HostWidget {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    static constexpr uint32_t kMainBytes  = 0x1000u;
    static constexpr uint32_t kSpareBytes = 0x200u;

    /* Full NAND page at main-flash offset `main_off` (4 KB-aligned); an unwritten or
       erased page yields main = spare = 0xFF. Bytes are RAW: the NFC applies the
       main[0xF4A]<->spare[0x1C1] BBI swap, so storing served-form here double-swaps. */
    void ReadPage (uint64_t main_off, uint8_t* main, uint8_t* spare);
    void WritePage(uint64_t main_off, const uint8_t* main, const uint8_t* spare);

    /* Erase the 512 KB block containing `main_off` -> every page reads 0xFF
       (punch a hole so the backing reads 0x00 -> complements to 0xFF). */
    void EraseBlock(uint64_t main_off);

    /* Main-bytes-only read for the mask-ROM IPL stage/scan (within one page). */
    void ReadMain(uint64_t main_off, void* dst, uint32_t len);

    /* Total device page count (4 KB main pages), valid after OnReady. */
    uint64_t DevicePages() const { return device_pages_; }

    std::string ImagePath() const;

    /* Register an in-memory page ReadPage returns for `page_index` (raw
       main+spare), used by guest-additions IMGFS injection. */
    void SetReadOverlayPage(uint64_t page_index, const uint8_t* main,
                            const uint8_t* spare);

    std::wstring WidgetName() const override { return L"NAND Flash"; }
    WidgetGroup  Group() const override { return WidgetGroup::Storage; }
    std::wstring Tooltip() const override;
    void         DrawIcon(HDC dc, const RECT& box) const override;

private:
    /* 2 GB Micron part (NFC READ ID 0x2C/0x48), 512 KB block, 4 KB page. */
    static constexpr uint64_t kDeviceBytes   = 0x80000000u;
    static constexpr uint64_t kBlock         = 0x80000u;
    static constexpr uint32_t kPageStride    = kMainBytes + kSpareBytes;     /* 0x1200 */
    static constexpr uint32_t kSectorsPerPage = kPageStride / DiskImage::kSectorSize; /* 9 */
    static constexpr uint32_t kPagesPerBlock = kBlock / kMainBytes;          /* 128 */

    void Seed();
    static uint32_t MainPopcount(const uint8_t* main);

    DiskImage img_;
    uint64_t  device_pages_ = 0;
    std::unordered_map<uint64_t, std::array<uint8_t, kPageStride>> read_overlay_;
};
