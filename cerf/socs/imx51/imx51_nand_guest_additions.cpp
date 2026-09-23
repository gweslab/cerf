#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include "imx51_nand_imgfs_view.h"
#include "imx51_nand_store.h"

#include "../../boot/ce_imgfs_patcher.h"
#include "../../boot/ce_imgfs_walker.h"
#include "../../boot/guest_additions_binaries.h"
#include "../../boot/imgfs_victim_recomposer.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../core/service.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <set>
#include <vector>

namespace {

using cerf::ce_imgfs_walker::kDirentFileSizeOff;
using cerf::ce_imgfs_walker::kImgfsPageSize;

class Imx51NandGuestAdditions : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        if (!bd || bd->GetRomPlacingMode() != RomPlacingMode::Imx51Nand)
            return false;
        if (!emu_.Get<DeviceConfig>().guest_additions) return false;
        return emu_.TryGet<Imx51NandStore>() != nullptr;
    }

    void OnReady() override {
        auto& view = emu_.Get<Imx51NandImgfsView>();
        if (!view.Located()) return;  /* the view logged the reason */

        const auto& victims = emu_.Get<DeviceConfig>().guest_additions_victims;
        if (victims.empty()) {
            LOG(Caution, "[NandGA] guest_additions on but no "
                "video_driver_names_for_guest_additions configured\n");
            return;
        }
        base_page_ = view.VolumeBasePage();
        const std::string stub_path = emu_.Get<GuestAdditionsBinaries>().StubPath();

        int replaced = 0;
        for (const auto& victim : victims)
            for (const auto& m : view.Modules())
                if (_stricmp(m.name.c_str(), victim.c_str()) == 0)
                    if (Inject(m, view.Volume(), stub_path)) ++replaced;
        LOG(GuestAdditions, "[NandGA] %d victim(s) replaced in NAND IMGFS\n", replaced);
    }

private:
    void PatchVolume(uint64_t logical_off, const uint8_t* data, uint32_t len) {
        auto& store = emu_.Get<Imx51NandStore>();
        uint32_t done = 0;
        while (done < len) {
            const uint64_t voff  = logical_off + done;
            const uint64_t page  = base_page_ + voff / kImgfsPageSize;
            const uint32_t in_pg = uint32_t(voff % kImgfsPageSize);
            const uint32_t n     = std::min<uint32_t>(kImgfsPageSize - in_pg, len - done);
            std::array<uint8_t, Imx51NandStore::kMainBytes>  main{};
            std::array<uint8_t, Imx51NandStore::kSpareBytes> spare{};
            store.ReadPage(page * Imx51NandStore::kMainBytes, main.data(), spare.data());
            std::memcpy(main.data() + in_pg, data + done, n);
            store.SetReadOverlayPage(page, main.data(), spare.data());
            done += n;
        }
    }

    void WritePageBytes(uint32_t logical_page, const uint8_t* src, uint32_t real_size) {
        std::array<uint8_t, kImgfsPageSize> buf{};
        std::memcpy(buf.data(), src, std::min<uint32_t>(real_size, kImgfsPageSize));
        PatchVolume(uint64_t(logical_page) * kImgfsPageSize, buf.data(), kImgfsPageSize);
    }

    /* Logical data pages the victim's own module-header + section index blocks
       reference - freed by the replacement, reused as the stub's page pool. */
    std::vector<uint32_t> BuildFreePool(const cerf::ce_imgfs_walker::ImgfsModule& m,
                                        std::span<const uint8_t> vol,
                                        const cerf::ce_imgfs_walker::Translator& tr) {
        std::set<uint32_t> pages;
        auto collect = [&](uint32_t indexptr, uint32_t indexsize) {
            if (!indexptr || !indexsize) return;
            const std::vector<uint8_t> idx = tr.Read(vol, indexptr, indexsize);
            using cerf::ce_imgfs_walker::kIndexRecSize;
            for (size_t o = 0; o + kIndexRecSize <= idx.size(); o += kIndexRecSize) {
                const auto rec = cerf::ce_imgfs_walker::ReadIndexRecord(idx.data() + o);
                if (rec.IsTerminator()) break;
                if (rec.ptr == 0) continue;
                const uint32_t first = rec.ptr / kImgfsPageSize;
                const uint32_t last  = cerf::ce_imgfs_walker::PagesFor(size_t(rec.ptr) + rec.comp_size);
                for (uint32_t p = first; p < last; ++p) pages.insert(p);
            }
        };
        collect(m.mod_indexptr, m.mod_indexsize);
        for (const auto& s : m.sections) collect(s.sec_indexptr, s.sec_indexsize);
        return {pages.begin(), pages.end()};
    }

    bool Inject(const cerf::ce_imgfs_walker::ImgfsModule& victim,
                std::span<const uint8_t> vol, const std::string& stub_path) {
        auto tr = cerf::ce_imgfs_walker::Translator::Detect(vol, /*imgfs_base=*/0);
        const std::vector<uint8_t> orig_hdr = cerf::ce_imgfs_walker::ReadIndexData(
            vol, tr, victim.mod_indexptr, victim.mod_indexsize, victim.file_size);
        auto rc = emu_.Get<ImgfsVictimRecomposer>().Recompose(
            orig_hdr, victim.sections.size(), stub_path);
        if (!rc) return false;
        const std::vector<uint8_t>& new_hdr = rc->new_hdr;
        const auto& slots = rc->slots;

        std::vector<uint32_t> pool = BuildFreePool(victim, vol, tr);
        size_t next = 0;
        auto take = [&](uint32_t count) -> std::vector<uint32_t> {
            if (next + count > pool.size()) {
                LOG(Caution, "[NandGA] victim footprint too small: need %u, have %zu\n",
                    count, pool.size() - next);
                CerfFatalExit();
            }
            std::vector<uint32_t> out(pool.begin() + next, pool.begin() + next + count);
            next += count;
            return out;
        };

        /* Module header -> one freed page; repoint the module index block. */
        const uint32_t hdr_page = take(1)[0];
        WritePageBytes(hdr_page, new_hdr.data(), uint32_t(new_hdr.size()));
        const auto mod_idx = cerf::ce_imgfs_patcher::BuildIndexBlock(
            uint32_t(new_hdr.size()), hdr_page * kImgfsPageSize);
        PatchVolume(victim.mod_indexptr, mod_idx.data(), uint32_t(mod_idx.size()));
        const uint32_t hdr_size = uint32_t(new_hdr.size());
        PatchVolume(victim.dirent_off + kDirentFileSizeOff,
                    reinterpret_cast<const uint8_t*>(&hdr_size), 4);

        /* Each stub slot -> freed pages; repoint that section's index block. */
        for (size_t i = 0; i < slots.size(); ++i) {
            const auto& s = slots[i];
            const std::vector<uint32_t> pg = take(cerf::ce_imgfs_walker::PagesFor(s.bytes.size()));
            const auto recs = cerf::ce_imgfs_patcher::WritePagedData(
                s.bytes, [&](uint32_t p, const uint8_t* data, uint32_t len) {
                    WritePageBytes(pg[p], data, len);
                    return pg[p] * kImgfsPageSize;
                });
            const auto sec_idx = cerf::ce_imgfs_patcher::BuildIndexBlock(recs);
            PatchVolume(victim.sections[i].sec_indexptr, sec_idx.data(),
                        uint32_t(sec_idx.size()));
            const uint32_t sec_size = uint32_t(s.bytes.size());
            PatchVolume(victim.sections[i].dirent_off + kDirentFileSizeOff,
                        reinterpret_cast<const uint8_t*>(&sec_size), 4);
        }

        LOG(GuestAdditions, "[NandGA] '%s' replaced: slots=%zu hdr=%zu pool=%zu\n",
            victim.name.c_str(), slots.size(), new_hdr.size(), pool.size());
        return true;
    }

    uint64_t base_page_ = 0;
};

}  // namespace

REGISTER_SERVICE(Imx51NandGuestAdditions);
