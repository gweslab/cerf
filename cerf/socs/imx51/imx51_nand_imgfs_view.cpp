#include "imx51_nand_imgfs_view.h"

#include "imx51_nand_store.h"

#include "../../boards/board_context.h"
#include "../../boot/rom_image_parse.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"

#include <algorithm>
#include <array>

REGISTER_SERVICE(Imx51NandImgfsView);

namespace {

using cerf::rom_image_parse::ImgfsSuperblock;
using cerf::rom_image_parse::ReadImgfsSuperblock;

/* Bound on the reconstructed span held in one Win32 (32-bit) allocation.
   Over-reading past the IMGFS partition is harmless - the walker only acts on
   dir-magic blocks. */
constexpr uint64_t kReconstructCap = 0x04000000ull;

bool SanePageSize(uint32_t v) {
    return v >= 0x200 && v <= 0x100000 && (v & (v - 1)) == 0;
}

}  // namespace

bool Imx51NandImgfsView::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    if (!bd || bd->GetRomPlacingMode() != RomPlacingMode::Imx51Nand) return false;
    if (!emu_.Get<DeviceConfig>().guest_additions) return false;
    return emu_.TryGet<Imx51NandStore>() != nullptr;
}

void Imx51NandImgfsView::OnReady() {
    if (!LocateVolume()) {
        LOG(GuestAdditions, "[NandImgfs] IMGFS volume not found in storage.nand %s\n",
            emu_.Get<Imx51NandStore>().ImagePath().c_str());
        return;
    }
    ReconstructAndWalk();
}

bool Imx51NandImgfsView::LocateVolume() {
    auto& nand = emu_.Get<Imx51NandStore>();
    const uint64_t pages = nand.DevicePages();
    std::array<uint8_t, 0x30> hdr{};
    for (uint64_t p = 0; p < pages; ++p) {
        nand.ReadMain(p * Imx51NandStore::kMainBytes, hdr.data(),
                      uint32_t(hdr.size()));
        ImgfsSuperblock sb;
        if (!ReadImgfsSuperblock(hdr, 0, sb)) continue;
        const uint32_t bpb = sb.bytes_per_block;
        if (!SanePageSize(bpb)) continue;
        base_page_ = p;
        bpb_       = bpb;
        located_   = true;
        LOG(GuestAdditions, "[NandImgfs] volume header @ NAND page %llu "
            "(byte 0x%llX) bpb=0x%X\n",
            static_cast<unsigned long long>(p),
            static_cast<unsigned long long>(p * Imx51NandStore::kMainBytes), bpb);
        return true;
    }
    return false;
}

void Imx51NandImgfsView::ReconstructAndWalk() {
    auto& nand = emu_.Get<Imx51NandStore>();
    const uint64_t avail =
        (nand.DevicePages() - base_page_) * Imx51NandStore::kMainBytes;
    const uint64_t span   = std::min<uint64_t>(avail, kReconstructCap);
    const uint64_t npages = span / Imx51NandStore::kMainBytes;

    vol_.assign(static_cast<size_t>(npages * Imx51NandStore::kMainBytes), 0);
    for (uint64_t i = 0; i < npages; ++i) {
        nand.ReadMain((base_page_ + i) * Imx51NandStore::kMainBytes,
                      vol_.data() + static_cast<size_t>(i * Imx51NandStore::kMainBytes),
                      Imx51NandStore::kMainBytes);
    }

    auto tr = cerf::ce_imgfs_walker::Translator::Detect(vol_, /*imgfs_base=*/0);
    modules_ = cerf::ce_imgfs_walker::CollectModules(vol_, tr, bpb_);
    LOG(GuestAdditions, "[NandImgfs] reconstructed %llu MB, IMGFS %s, %zu module(s)\n",
        static_cast<unsigned long long>(span / (1024 * 1024)),
        tr.IsFtl() ? "FTL-mapped" : "direct-addressed",
        modules_.size());
}
