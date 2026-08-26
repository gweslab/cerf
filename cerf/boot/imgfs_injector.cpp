#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include "imgfs_injector.h"

#include "ce_imgfs_patcher.h"
#include "ce_imgfs_walker.h"
#include "imgfs_victim_recomposer.h"
#include "rom_parser_queries.h"
#include "rom_parser_service.h"

#include "../boards/board_context.h"
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

constexpr uint32_t kE32SubsysmajorOff = 0x0C;
constexpr uint32_t kE32VbaseOff       = 0x08;
constexpr uint32_t kDirentFileSizeOff = 0x18;

inline uint32_t Rd32(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8)
         | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

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
        const uint16_t sub = mem.ReadHalf(e32_pa + kE32SubsysmajorOff);
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

    constexpr uint32_t kErase = 0x10000;
    constexpr uint32_t kPage  = 0x1000;
    constexpr uint32_t kDpb   = 15;
    const size_t imgfs_size = rom.raw.size() - rom.imgfs_file_off;
    const size_t num_blocks = imgfs_size / kErase;
    uint32_t max_ls = 0;
    for (size_t blk = 0; blk < num_blocks; ++blk) {
        const size_t map_off = rom.imgfs_file_off + blk * kErase + kDpb * kPage;
        for (uint32_t e = 0; e < kDpb; ++e) {
            const size_t eo = map_off + e * 8;
            if (eo + 8 > rom.raw.size()) break;
            const uint32_t ls = Rd32(rom.raw.data() + eo);
            if (ls == 0xFFFFFFFFu) {
                free_ftl_slots_.push_back(
                    {uint32_t(blk), e, uint32_t(blk * (kDpb + 1) + e)});
            } else if (ls > max_ls) {
                max_ls = ls;
            }
        }
    }
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

    constexpr uint32_t kErase  = 0x10000;
    constexpr uint32_t kPage   = 0x1000;
    constexpr uint32_t kDpb    = 15;
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
            const uint32_t map_entry_file_off = uint32_t(
                rom.imgfs_file_off + slot.block_idx * kErase
                + kDpb * kPage + slot.entry_idx * 8);
            const uint32_t map_entry_pa = flash_pa_base_ + map_entry_file_off;
            const uint32_t pre_ls = mem.ReadWord(map_entry_pa + 0);
            const uint32_t pre_fl = mem.ReadWord(map_entry_pa + 4);
            mem.WriteWord(map_entry_pa + 0, new_ls);
            mem.WriteWord(map_entry_pa + 4, kValidFlags);
            const uint32_t post_ls = mem.ReadWord(map_entry_pa + 0);
            const uint32_t post_fl = mem.ReadWord(map_entry_pa + 4);
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
                + uint32_t(rom.imgfs_file_off + slot.phys_page_idx * kPage);
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
        for (uint32_t b = real_size; b < kPage; ++b) {
            mem.WriteByte(pa + b, 0);
        }
    };

    /* Module header (e32_rom + o32 array, ~200 bytes for cerf_guest)
       - one fresh 4 KB page. */
    auto hdr_pages = allocate_pages(1, "mod_hdr");
    const uint32_t hdr_la = hdr_pages[0].first * kPage;
    const uint32_t hdr_pa = hdr_pages[0].second;
    write_bytes_to_page(hdr_pa, new_hdr.data(), uint32_t(new_hdr.size()));
    LOG(GuestAdditions, "[ImgfsInjector] %s mod_hdr: la=0x%08X pa=0x%08X size=%zu\n",
        victim_name, hdr_la, hdr_pa, new_hdr.size());

    /* Verify the header write landed: read back e32_vbase (off 0x08) from the
       patched header page and compare to the vbase the recomposed header carries.
       Mismatch means the DRAM write didn't take. */
    const uint32_t expected_vbase = Rd32(new_hdr.data() + kE32VbaseOff);
    const uint32_t verify_vbase   = mem.ReadWord(hdr_pa + kE32VbaseOff);
    if (verify_vbase != expected_vbase) {
        LOG(Caution, "[ImgfsInjector] %s VERIFY FAIL: hdr e32_vbase "
                "expected 0x%08X got 0x%08X\n",
                victim_name, expected_vbase, verify_vbase);
        CerfFatalExit();
    }

    std::vector<cerf::ce_imgfs_patcher::IndexRec> mod_recs = {{kPage, hdr_la}};
    const auto mod_idx_new = cerf::ce_imgfs_patcher::BuildIndexBlock(mod_recs);
    auto mod_idx_pages = allocate_pages(1, "mod_idx");
    const uint32_t mod_idx_la = mod_idx_pages[0].first * kPage;
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
        const uint32_t pages_needed = (uint32_t(s.bytes.size()) + kPage - 1) / kPage;
        auto sec_pages = allocate_pages(pages_needed, "sec_data");
        std::vector<cerf::ce_imgfs_patcher::IndexRec> sec_recs;
        sec_recs.reserve(pages_needed);
        for (uint32_t p = 0; p < pages_needed; ++p) {
            const uint32_t la = sec_pages[p].first * kPage;
            const uint32_t pa = sec_pages[p].second;
            const uint32_t off   = p * kPage;
            const uint32_t chunk = std::min<uint32_t>(
                kPage, uint32_t(s.bytes.size()) - off);
            write_bytes_to_page(pa, s.bytes.data() + off, chunk);
            sec_recs.push_back({kPage, la});
        }
        LOG(GuestAdditions,
            "[ImgfsInjector] %s sec[%zu]: %u pages, vsize=%u psize=%u rva=0x%X\n",
            victim_name, i, pages_needed, s.vsize, s.psize, s.rva);

        const auto sec_idx_new =
            cerf::ce_imgfs_patcher::BuildIndexBlock(sec_recs);
        auto sec_idx_pages = allocate_pages(1, "sec_idx");
        const uint32_t sec_idx_la = sec_idx_pages[0].first * kPage;
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
