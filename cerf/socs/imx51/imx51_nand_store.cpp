#include "imx51_nand_store.h"
#include "imx51_nand_layout.h"

#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../boot/sec_flash.h"
#include "../../core/cerf_emulator.h"
#include "../../core/cerf_paths.h"
#include "../../core/device_config.h"
#include "../../core/host_file_bytes.h"
#include "../../core/log.h"
#include "../../host/host_widget_registry.h"

#include <array>
#include <cstring>

REGISTER_SERVICE(Imx51NandStore);

std::string Imx51NandStore::ImagePath() const {
    const DeviceConfig& cfg = emu_.Get<DeviceConfig>();
    return ResolveDeviceFile(cfg.device_name, cfg.storage_nand);
}

std::wstring Imx51NandStore::Tooltip() const {
    return L"NAND Flash storage (" + Utf8ToWide(ImagePath().c_str()) + L")";
}

bool Imx51NandStore::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    if (!bd || bd->GetSocId() != SocId::Imx51) return false;
    auto* sf = emu_.TryGet<SecFlash>();
    if (sf && sf->IsPresent()) return true;   /* can seed/flash from the `.sec` */
    return HostFileNonEmpty(ImagePath());
}

void Imx51NandStore::OnReady() {
    device_pages_ = kDeviceBytes / kMainBytes;

    const std::string path = ImagePath();
    const bool existed = HostFileNonEmpty(path);

    if (!img_.Open(path, device_pages_ * kPageStride)) {
        LOG(Caution, "Imx51NandStore: cannot open '%s'\n", path.c_str());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    emu_.Get<HostWidgetRegistry>().Register(this);

    if (existed) {
        LOG(SocNand, "Imx51NandStore: using existing '%s' (%llu pages)\n",
            path.c_str(), static_cast<unsigned long long>(device_pages_));
        return;
    }

    auto* sf = emu_.TryGet<SecFlash>();
    if (!sf || !sf->IsPresent()) {
        LOG(Caution, "Imx51NandStore: no '%s' and no `.sec` to seed/flash from\n",
            path.c_str());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    LOG(SocNand, "Imx51NandStore: synthesizing '%s' - seeding factory boot region\n",
        path.c_str());
    Seed();
}

void Imx51NandStore::ReadPage(uint64_t main_off, uint8_t* main, uint8_t* spare) {
    MarkRx();
    const uint64_t page = main_off / kMainBytes;
    if (auto ov = read_overlay_.find(page); ov != read_overlay_.end()) {
        std::memcpy(main,  ov->second.data(),              kMainBytes);
        std::memcpy(spare, ov->second.data() + kMainBytes, kSpareBytes);
        return;
    }
    std::array<uint8_t, kPageStride> buf{};
    if (page >= device_pages_ ||
        !img_.ReadSectors(page * kSectorsPerPage, kSectorsPerPage, buf.data())) {
        std::memset(main,  0xFF, kMainBytes);
        std::memset(spare, 0xFF, kSpareBytes);
        return;
    }
    for (auto& b : buf) b = static_cast<uint8_t>(~b);
    std::memcpy(main,  buf.data(),              kMainBytes);
    std::memcpy(spare, buf.data() + kMainBytes, kSpareBytes);
}

void Imx51NandStore::WritePage(uint64_t main_off, const uint8_t* main, const uint8_t* spare) {
    MarkTx();
    const uint64_t page = main_off / kMainBytes;
    if (page >= device_pages_) {
        LOG(Caution, "Imx51NandStore: program out-of-range page %llu (off 0x%llX)\n",
            static_cast<unsigned long long>(page), static_cast<unsigned long long>(main_off));
        return;
    }
    std::array<uint8_t, kPageStride> buf{};
    std::memcpy(buf.data(),              main,  kMainBytes);
    std::memcpy(buf.data() + kMainBytes, spare, kSpareBytes);
    for (auto& b : buf) b = static_cast<uint8_t>(~b);
    if (!img_.WriteSectors(page * kSectorsPerPage, kSectorsPerPage, buf.data()))
        LOG(Caution, "Imx51NandStore: program write-fail page %llu\n",
            static_cast<unsigned long long>(page));
}

void Imx51NandStore::EraseBlock(uint64_t main_off) {
    const uint64_t first_page = (main_off / kBlock) * kPagesPerBlock;
    img_.PunchHole(first_page * kSectorsPerPage, kPagesPerBlock * kSectorsPerPage);
}

void Imx51NandStore::ReadMain(uint64_t main_off, void* dst, uint32_t len) {
    const uint64_t page  = main_off / kMainBytes;
    const uint32_t in_pg = static_cast<uint32_t>(main_off % kMainBytes);
    std::array<uint8_t, kMainBytes>  mbuf{};
    std::array<uint8_t, kSpareBytes> sbuf{};
    ReadPage(page * kMainBytes, mbuf.data(), sbuf.data());
    const uint32_t n = (in_pg + len <= kMainBytes) ? len : (kMainBytes - in_pg);
    std::memcpy(dst, mbuf.data() + in_pg, n);
    if (n < len) std::memset(static_cast<uint8_t*>(dst) + n, 0xFF, len - n);
}

void Imx51NandStore::Seed() {
    auto& layout = emu_.Get<Imx51NandLayout>();
    const uint64_t os_start   = layout.OsRegionStartBlock();
    const uint64_t dev_blocks = layout.DeviceBlocks();
    uint64_t seeded = 0;
    auto seed_block = [&](uint64_t blk) {
        for (uint32_t p = 0; p < kPagesPerBlock; ++p) {
            const uint64_t main_off = blk * kBlock + static_cast<uint64_t>(p) * kMainBytes;
            std::array<uint8_t, kMainBytes>  main{};
            std::array<uint8_t, kSpareBytes> spare{};
            if (layout.BuildFactoryPage(main_off, main.data(), kMainBytes,
                                        spare.data(), kSpareBytes)) {
                WritePage(main_off, main.data(), spare.data());
                ++seeded;
            }
        }
    };
    for (uint64_t blk = 0; blk < os_start; ++blk) seed_block(blk);
    if (dev_blocks >= 5) seed_block(dev_blocks - 5);   /* synthesized BBT */
    if (dev_blocks >= 1) seed_block(dev_blocks - 1);   /* synthesized DPS */
    LOG(SocNand, "Imx51NandStore: seeded %llu pages (boot region blocks 0..%llu + BBT/DPS)\n",
        static_cast<unsigned long long>(seeded),
        static_cast<unsigned long long>(os_start ? os_start - 1 : 0));
}

/* FileSysFal (AutoFlashMDD sub_C09A0FE0) validates its per-page checksum over the
   raw main bytes: the FMD un-swaps the NFC main[0xF4A]<->spare[0x1C1] BBI
   displacement (imx51_nfc.cpp FillPageBuffer) before checksumming, so index 0xF4A
   contributes its raw stored byte, not spare[0x1C1]. */
uint32_t Imx51NandStore::MainPopcount(const uint8_t* main) {
    auto pop = [](uint8_t b) -> uint32_t {
        b = uint8_t(b - ((b >> 1) & 0x55));
        b = uint8_t((b & 0x33) + ((b >> 2) & 0x33));
        return (b + (b >> 4)) & 0x0F;
    };
    uint32_t pc = 0;
    for (uint32_t i = 0; i < kMainBytes; ++i)
        pc += pop(main[i]);
    return pc;
}

void Imx51NandStore::SetReadOverlayPage(uint64_t page_index, const uint8_t* main,
                                        const uint8_t* spare) {
    std::array<uint8_t, kPageStride>& buf = read_overlay_[page_index];
    std::memcpy(buf.data(),              main,  kMainBytes);
    std::memcpy(buf.data() + kMainBytes, spare, kSpareBytes);

    /* Restamp the FileSysFal per-page spare checksum for the modified main, else the
       guest FAL read returns error 13 and the IMGFS mount fails. checksum =
       (MainPopcount + K) & 0xFFFF at spare 0x183(lo)/0x1C2(hi); K
       (=popcount logical+field2) is recovered as a delta from the backing page. */
    std::array<uint8_t, kPageStride> orig{};
    if (page_index < device_pages_ &&
        img_.ReadSectors(page_index * kSectorsPerPage, kSectorsPerPage, orig.data())) {
        for (auto& b : orig) b = static_cast<uint8_t>(~b);
        const uint8_t* om = orig.data();
        const uint8_t* os = orig.data() + kMainBytes;
        const uint32_t old_ck = os[0x183u] | (uint32_t(os[0x1C2u]) << 8);
        const uint32_t pc_orig = MainPopcount(om);
        const uint32_t k = (old_ck - pc_orig) & 0xFFFFu;
        const uint32_t pc_new = MainPopcount(main);
        const uint32_t new_ck = (pc_new + k) & 0xFFFFu;
        buf[kMainBytes + 0x183u] = static_cast<uint8_t>(new_ck & 0xFF);
        buf[kMainBytes + 0x1C2u] = static_cast<uint8_t>((new_ck >> 8) & 0xFF);
    }
}

void Imx51NandStore::DrawIcon(HDC dc, const RECT& box) const {
    DrawChipIcon(dc, box);
}
