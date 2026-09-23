#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include "imgfs_injector.h"

#include "ce_imgfs_patcher.h"
#include "ce_imgfs_walker.h"
#include "imgfs_victim_recomposer.h"
#include "rom_parser_queries.h"
#include "rom_parser_service.h"
#include "rom_record_layout.h"

#include "../boards/board_context.h"
#include "../core/byte_order.h"
#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../core/log.h"
#include "../cpu/emulated_memory.h"
#include "../boards/page_table_builder.h"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <vector>

REGISTER_SERVICE(ImgfsInjector);

namespace {

using cerf::ce_imgfs_walker::kDirentFileSizeOff;
using cerf::ce_imgfs_walker::kImgfsEraseBlock;
using cerf::ce_imgfs_walker::kImgfsPageSize;
using cerf::le::U32;

}  /* namespace */

bool ImgfsInjector::ShouldRegister() {
    if (!emu_.Get<DeviceConfig>().guest_additions) return false;
    return emu_.Get<BoardContext>().GetRomPlacingMode()
        == RomPlacingMode::FlatContainer;
}

void ImgfsInjector::OnReady() {
    auto& parser = emu_.Get<RomParserService>();
    if (!parser.Ok()) return;
    const auto& rom = parser.Primary();
    if (!rom.has_imgfs || rom.imgfs_modules.empty()) return;

    auto* nk = emu_.Get<RomParserQueries>().KernelModule();
    if (nk) {
        auto& pt = emu_.Get<PageTableBuilder>();
        auto& mem = emu_.Get<EmulatedMemory>();
        const uint32_t e32_pa = pt.VaToPa(nk->ulE32Offset);
        const uint16_t sub = mem.ReadHalf(e32_pa + kE32OffSubsysMajor);
        if (sub >= 3 && sub <= 8) ce_major_ = sub;
    }

    auto& pt = emu_.Get<PageTableBuilder>();
    if (rom.xips.empty()) {
        LOG(Caution, "[ImgfsInjector] rom has no XIPs; can't anchor flash PA\n");
        return;
    }
    bool have_flash = false;
    for (const auto& xip : rom.xips) {
        const uint32_t pa = pt.VaToPa(xip.load_offset);
        for (const auto& reg : pt.BackedMemoryRegions()) {
            if (reg.page_protect != PAGE_READONLY) continue;
            if (pa < reg.pa_base) continue;
            if (pa >= reg.pa_base + reg.size) continue;
            flash_pa_base_ = reg.pa_base;
            have_flash    = true;
            break;
        }
        if (have_flash) break;
    }
    if (!have_flash) {
        LOG(Caution, "[ImgfsInjector] no Flash backed region found "
                "across %zu xips\n", rom.xips.size());
        return;
    }
    flash_anchored_ = true;

    const size_t imgfs_size = rom.raw.size() - rom.imgfs_file_off;
    const size_t num_blocks = imgfs_size / kImgfsEraseBlock;
    uint32_t max_ls = 0;
    cerf::ce_imgfs_walker::ForEachFtlMapEntry(rom.raw, rom.imgfs_file_off, num_blocks,
        [&](size_t blk, uint32_t e, uint32_t ls, uint32_t) {
            if (ls == cerf::ce_imgfs_walker::kFtlErasedSector) {
                free_ftl_slots_.push_back(
                    {uint32_t(blk), e, cerf::ce_imgfs_walker::FtlPhysPage(blk, e)});
            } else if (ls > max_ls) {
                max_ls = ls;
            }
        });
    next_new_ls_ = max_ls + 1;

    LOG(GuestAdditions,
        "[ImgfsInjector] flash_pa_base=0x%08X imgfs_file_off=0x%X "
        "ce_major=%u modules=%zu ftl_free=%zu max_ls=0x%X\n",
        flash_pa_base_, rom.imgfs_file_off, ce_major_,
        rom.imgfs_modules.size(), free_ftl_slots_.size(), max_ls);
}

bool ImgfsInjector::ReplaceVictim(const char* victim_name,
                                   const std::string& source_path) {
    auto& parser = emu_.Get<RomParserService>();
    if (!parser.Ok()) return false;
    const auto& rom = parser.Primary();
    if (!rom.has_imgfs || !flash_anchored_) return false;

    const ParsedImgfsModule* victim = nullptr;
    for (const auto& m : rom.imgfs_modules) {
        if (_stricmp(m.lpszFileName.c_str(), victim_name) == 0) {
            victim = &m;
            break;
        }
    }
    if (!victim) return false;
    auto& mem = emu_.Get<EmulatedMemory>();

    auto tr = cerf::ce_imgfs_walker::Translator::Detect(
        rom.raw, rom.imgfs_file_off);

    /* MUST offset by base_sector - kernel resolves sector = LA/0x1000 + base_sector;
       omitting it walks to an unmapped sector and read returns empty. */
    const uint32_t base_sector = tr.BaseSector();

    const std::vector<uint8_t> orig_hdr = cerf::ce_imgfs_walker::ReadIndexData(
        rom.raw, tr, victim->mod_indexptr, victim->mod_indexsize,
        victim->file_size);
    auto rc = emu_.Get<ImgfsVictimRecomposer>().Recompose(
        orig_hdr, victim->sections.size(), source_path);
    if (!rc) CerfFatalExit();
    const std::vector<uint8_t>& new_hdr = rc->new_hdr;
    const auto& slots = rc->slots;

    auto translate_or_halt = [&](uint32_t la, const char* what) -> uint32_t {
        const size_t off = tr.Translate(la);
        if (off == SIZE_MAX || off > rom.raw.size()) {
            LOG(Caution, "[ImgfsInjector] %s %s la=0x%08X did not "
                    "translate (raw=%zu)\n",
                    victim_name, what, la, rom.raw.size());
            CerfFatalExit();
        }
        return flash_pa_base_ + uint32_t(off);
    };

    /* IMGFS FTL flag word: imgfs.dll skips an entry whose bit 18 is set
       (deleted-pending), so a live mapping clears it - 0xFFFBFFFF. */
    constexpr uint32_t kValidFlags = 0xFFFBFFFFu;

    auto allocate_pages = [&](uint32_t count, const char* what)
        -> std::vector<std::pair<uint32_t /*new_ls*/, uint32_t /*phys_pa*/>> {
        if (free_ftl_slots_.size() < count) {
            LOG(Caution, "[ImgfsInjector] %s %s out of free FTL pages: "
                    "need %u, have %zu\n",
                    victim_name, what, count, free_ftl_slots_.size());
            CerfFatalExit();
        }
        std::vector<std::pair<uint32_t, uint32_t>> out;
        out.reserve(count);
        for (uint32_t i = 0; i < count; ++i) {
            /* Fill each erase block from entry 0 up: the WM6.1 store-FAL mount
               scan (sub_3E4CCB4) frees and skips any block whose first data page
               is still erased, so a block written only at high entries is never
               adopted and its sectors read back zero (driver .data Data Abort). */
            const auto slot = free_ftl_slots_.front();
            free_ftl_slots_.erase(free_ftl_slots_.begin());
            const uint32_t new_ls = next_new_ls_++;
            using cerf::ce_imgfs_walker::kImgfsMapOffFlags;
            using cerf::ce_imgfs_walker::kImgfsMapOffSector;
            const uint32_t map_entry_file_off = uint32_t(cerf::ce_imgfs_walker::FtlMapEntryOffset(
                rom.imgfs_file_off, slot.block_idx, slot.entry_idx));
            const uint32_t map_entry_pa = flash_pa_base_ + map_entry_file_off;
            const uint32_t pre_ls = mem.ReadWord(map_entry_pa + kImgfsMapOffSector);
            const uint32_t pre_fl = mem.ReadWord(map_entry_pa + kImgfsMapOffFlags);
            mem.WriteWord(map_entry_pa + kImgfsMapOffSector, new_ls);
            mem.WriteWord(map_entry_pa + kImgfsMapOffFlags, kValidFlags);
            const uint32_t post_ls = mem.ReadWord(map_entry_pa + kImgfsMapOffSector);
            const uint32_t post_fl = mem.ReadWord(map_entry_pa + kImgfsMapOffFlags);
            LOG(GuestAdditions,
                "[ImgfsInjector] %s %s FTL slot blk=%u entry=%u pa=0x%08X: "
                "pre(ls=0x%08X fl=0x%08X) -> post(ls=0x%08X fl=0x%08X) "
                "phys_page=%u new_ls=0x%X\n",
                victim_name, what, slot.block_idx, slot.entry_idx,
                map_entry_pa, pre_ls, pre_fl, post_ls, post_fl,
                slot.phys_page_idx, new_ls);
            if (post_ls != new_ls || post_fl != kValidFlags) {
                LOG(Caution, "[ImgfsInjector] FTL write VERIFY FAIL\n");
                CerfFatalExit();
            }
            const uint32_t phys_page_pa = flash_pa_base_
                + uint32_t(rom.imgfs_file_off + slot.phys_page_idx * kImgfsPageSize);
            if (new_ls < base_sector) {
                LOG(Caution, "[ImgfsInjector] new_ls=0x%X < base_sector=0x%X\n",
                    new_ls, base_sector);
                CerfFatalExit();
            }
            out.push_back({new_ls - base_sector, phys_page_pa});
        }
        return out;
    };

    auto write_bytes_to_page = [&](uint32_t pa,
                                    const uint8_t* src,
                                    uint32_t real_size) {
        for (uint32_t b = 0; b < real_size; ++b) {
            mem.WriteByte(pa + b, src[b]);
        }
        for (uint32_t b = real_size; b < kImgfsPageSize; ++b) {
            mem.WriteByte(pa + b, 0);
        }
    };

    /* Module header (e32_rom + o32 array, ~200 bytes for cerf_guest)
       - one fresh 4 KB page. */
    auto hdr_pages = allocate_pages(1, "mod_hdr");
    const uint32_t hdr_la = hdr_pages[0].first * kImgfsPageSize;
    const uint32_t hdr_pa = hdr_pages[0].second;
    write_bytes_to_page(hdr_pa, new_hdr.data(), uint32_t(new_hdr.size()));
    LOG(GuestAdditions, "[ImgfsInjector] %s mod_hdr: la=0x%08X pa=0x%08X size=%zu\n",
        victim_name, hdr_la, hdr_pa, new_hdr.size());

    /* Verify the header write landed: read back e32_vbase (off 0x08) from the
       patched header page and compare to the vbase the recomposed header carries.
       Mismatch means the DRAM write didn't take. */
    const uint32_t expected_vbase = U32(new_hdr.data(), kE32OffVbase);
    const uint32_t verify_vbase   = mem.ReadWord(hdr_pa + kE32OffVbase);
    if (verify_vbase != expected_vbase) {
        LOG(Caution, "[ImgfsInjector] %s VERIFY FAIL: hdr e32_vbase "
                "expected 0x%08X got 0x%08X\n",
                victim_name, expected_vbase, verify_vbase);
        CerfFatalExit();
    }

    std::vector<cerf::ce_imgfs_patcher::IndexRec> mod_recs = {{kImgfsPageSize, hdr_la}};
    const auto mod_idx_new = cerf::ce_imgfs_patcher::BuildIndexBlock(mod_recs);
    auto mod_idx_pages = allocate_pages(1, "mod_idx");
    const uint32_t mod_idx_la = mod_idx_pages[0].first * kImgfsPageSize;
    const uint32_t mod_idx_pa = mod_idx_pages[0].second;
    write_bytes_to_page(mod_idx_pa, mod_idx_new.data(),
                        uint32_t(mod_idx_new.size()));
    const uint32_t mod_dirent_pa =
        flash_pa_base_ + uint32_t(victim->dirent_file_off);
    mem.WriteWord(mod_dirent_pa + cerf::ce_imgfs_walker::kModuleIndexPtrOff,
                  mod_idx_la);
    mem.WriteWord(mod_dirent_pa + cerf::ce_imgfs_walker::kModuleIndexSizeOff,
                  uint32_t(mod_idx_new.size()));
    mem.WriteWord(mod_dirent_pa + kDirentFileSizeOff,
                  uint32_t(new_hdr.size()));

    /* Sections - each in its own fresh contiguous run of 4 KB pages.
       Records advertise full_sz = 4 KB so the kernel's section-read
       walker (imgfs.dll sub_3E4574C) indexes them correctly by
       (offset >> 12). */
    for (size_t i = 0; i < slots.size(); ++i) {
        const auto& s = slots[i];
        const auto& sec_dir = victim->sections[i];
        const uint32_t pages_needed = cerf::ce_imgfs_walker::PagesFor(s.bytes.size());
        auto sec_pages = allocate_pages(pages_needed, "sec_data");
        const auto sec_recs = cerf::ce_imgfs_patcher::WritePagedData(
            s.bytes, [&](uint32_t p, const uint8_t* data, uint32_t len) {
                write_bytes_to_page(sec_pages[p].second, data, len);
                return sec_pages[p].first * kImgfsPageSize;
            });
        LOG(GuestAdditions,
            "[ImgfsInjector] %s sec[%zu]: %u pages, vsize=%u psize=%u rva=0x%X\n",
            victim_name, i, pages_needed, s.vsize, s.psize, s.rva);

        const auto sec_idx_new =
            cerf::ce_imgfs_patcher::BuildIndexBlock(sec_recs);
        auto sec_idx_pages = allocate_pages(1, "sec_idx");
        const uint32_t sec_idx_la = sec_idx_pages[0].first * kImgfsPageSize;
        const uint32_t sec_idx_pa = sec_idx_pages[0].second;
        write_bytes_to_page(sec_idx_pa, sec_idx_new.data(),
                            uint32_t(sec_idx_new.size()));
        const uint32_t sec_dirent_pa =
            flash_pa_base_ + uint32_t(sec_dir.dirent_file_off);
        mem.WriteWord(sec_dirent_pa + cerf::ce_imgfs_walker::kSectionIndexPtrOff,
                      sec_idx_la);
        mem.WriteWord(sec_dirent_pa + cerf::ce_imgfs_walker::kSectionIndexSizeOff,
                      uint32_t(sec_idx_new.size()));
        mem.WriteWord(sec_dirent_pa + kDirentFileSizeOff,
                      uint32_t(s.bytes.size()));
    }

    LOG(GuestAdditions, "[ImgfsInjector] %s injected: slots=%zu hdr=%zu\n",
        victim_name, slots.size(), new_hdr.size());
    return true;
}
