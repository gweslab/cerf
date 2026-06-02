#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include "imgfs_injector.h"

#include "ce_image_relocator.h"
#include "ce_imgfs_patcher.h"
#include "ce_imgfs_walker.h"
#include "pe_image.h"
#include "rom_parser_service.h"

#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../core/log.h"
#include "../cpu/emulated_memory.h"
#include "../boards/page_table_builder.h"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <vector>

REGISTER_SERVICE(ImgfsInjector);

namespace {

constexpr uint32_t kE32SubsysmajorOff = 0x0C;
constexpr uint32_t kE32VbaseOff       = 0x08;
constexpr uint32_t kE32ObjcntOff      = 0x00;
constexpr uint32_t kE32HeaderO32Base  = 0x70;
constexpr uint32_t kO32Size           = 24;
constexpr uint32_t kO32RvaOff         = 4;
constexpr uint32_t kO32RealaddrOff    = 16;
constexpr uint32_t kDirentFileSizeOff = 0x18;
constexpr uint32_t kIndexRecSize      = 8;

constexpr cerf::ce_imgfs_patcher::E32Layout kE32RomCE5plus = {
    /*size           */ 110,
    /*off_objcnt     */ 0x00,
    /*off_imageflags */ 0x02,
    /*off_entryrva   */ 0x04,
    /*off_vbase      */ 0x08,
    /*off_subsysmajor*/ 0x0C,
    /*off_subsysminor*/ 0x0E,
    /*off_stackmax   */ 0x10,
    /*off_vsize      */ 0x14,
    /*off_sect14rva  */ 0x18,
    /*off_sect14size */ 0x1C,
    /*off_timestamp  */ 0x20,
    /*off_unit       */ 0x24,
    /*off_subsys     */ 0x6C,
};

inline uint16_t Rd16(const uint8_t* p) {
    return uint16_t(p[0]) | (uint16_t(p[1]) << 8);
}
inline uint32_t Rd32(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8)
         | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

}  /* namespace */

bool ImgfsInjector::ShouldRegister() {
    if (!emu_.Get<DeviceConfig>().guest_additions) return false;
    return true;
}

void ImgfsInjector::OnReady() {
    auto& parser = emu_.Get<RomParserService>();
    if (!parser.Ok()) return;
    const auto& rom = parser.Primary();
    if (!rom.has_imgfs || rom.imgfs_modules.empty()) return;

    auto* nk = parser.KernelModule();
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
    if (victim->sections.empty()) {
        LOG(Caution, "[ImgfsInjector] %s has zero SECTION dirents; "
                "can't inject\n", victim_name);
        CerfFatalExit();
    }

    auto& mem = emu_.Get<EmulatedMemory>();

    auto tr = cerf::ce_imgfs_walker::Translator::Detect(
        rom.raw, rom.imgfs_file_off);

    /* MUST offset by base_sector — kernel resolves sector = LA/0x1000 + base_sector;
       omitting it walks to an unmapped sector and read returns empty. */
    const uint32_t base_sector = tr.BaseSector();

    std::vector<uint8_t> orig_hdr = cerf::ce_imgfs_walker::ReadIndexData(
        rom.raw, tr, victim->mod_indexptr, victim->mod_indexsize,
        victim->file_size);
    if (orig_hdr.size() < kE32HeaderO32Base) {
        LOG(Caution, "[ImgfsInjector] %s orig header too short (%zu bytes)\n",
            victim_name, orig_hdr.size());
        CerfFatalExit();
    }

    const uint32_t orig_vbase  = Rd32(orig_hdr.data() + kE32VbaseOff);
    const uint16_t orig_objcnt = Rd16(orig_hdr.data() + kE32ObjcntOff);
    if (orig_objcnt == 0
        || size_t(kE32HeaderO32Base) + size_t(orig_objcnt) * kO32Size > orig_hdr.size()) {
        LOG(Caution, "[ImgfsInjector] %s orig objcnt=%u inconsistent with "
                "header size %zu\n", victim_name, orig_objcnt, orig_hdr.size());
        CerfFatalExit();
    }
    const uint32_t orig_realaddr0 = Rd32(
        orig_hdr.data() + kE32HeaderO32Base + 0 * kO32Size + kO32RealaddrOff);
    const uint32_t orig_rva0 = Rd32(
        orig_hdr.data() + kE32HeaderO32Base + 0 * kO32Size + kO32RvaOff);
    const uint32_t slot_base = orig_realaddr0 - orig_rva0 - orig_vbase;
    LOG(GuestAdditions,
        "[ImgfsInjector] orig %s vbase=0x%08X objcnt=%u realaddr0=0x%08X "
        "rva0=0x%08X slot_base=0x%08X imgfs_secs=%zu\n",
        victim_name, orig_vbase, orig_objcnt, orig_realaddr0, orig_rva0,
        slot_base, victim->sections.size());

    std::ifstream f(source_path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) {
        LOG(Caution, "[ImgfsInjector] cannot open %s\n", source_path.c_str());
        CerfFatalExit();
    }
    const auto sz = f.tellg();
    std::vector<uint8_t> pe_bytes(static_cast<size_t>(sz));
    f.seekg(0);
    f.read(reinterpret_cast<char*>(pe_bytes.data()), sz);

    PeImage pe(std::move(pe_bytes));
    if (!pe.Parsed()) {
        LOG(Caution, "[ImgfsInjector] PE parse failed for %s\n",
            source_path.c_str());
        CerfFatalExit();
    }

    std::vector<uint8_t> pe_bytes_relocated(pe.Bytes().begin(), pe.Bytes().end());
    const int32_t delta = int32_t(orig_vbase) - int32_t(pe.ImageBase());
    uint32_t reloc_count = 0, unhandled = 0;
    cerf::ce_image_relocator::ApplyRelocations(
        pe_bytes_relocated, pe, delta, reloc_count, unhandled);
    if (unhandled > 0) {
        LOG(Caution, "[ImgfsInjector] %s has %u unhandled relocation entries\n",
            victim_name, unhandled);
        CerfFatalExit();
    }

    const size_t K = victim->sections.size();
    auto slots = cerf::ce_imgfs_patcher::PackPeSections(
        pe, pe_bytes_relocated, K);
    if (slots.empty() || slots.size() > K) {
        LOG(Caution, "[ImgfsInjector] %s packing yielded %zu slots (K=%zu)\n",
            victim_name, slots.size(), K);
        CerfFatalExit();
    }

    auto new_hdr = cerf::ce_imgfs_patcher::BuildModuleHeader(
        kE32RomCE5plus, pe, orig_vbase, slots);

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
    /* DO NOT use 0xFFFFFFFF — bit 18 set marks entry as deleted-pending
       and imgfs.dll skips it; every live mapping uses 0xFFFBFFFF. */
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
       — one fresh 4 KB page. */
    auto hdr_pages = allocate_pages(1, "mod_hdr");
    const uint32_t hdr_la = hdr_pages[0].first * kPage;
    const uint32_t hdr_pa = hdr_pages[0].second;
    write_bytes_to_page(hdr_pa, new_hdr.data(), uint32_t(new_hdr.size()));
    LOG(GuestAdditions, "[ImgfsInjector] %s mod_hdr: la=0x%08X pa=0x%08X size=%zu\n",
        victim_name, hdr_la, hdr_pa, new_hdr.size());

    /* Verify the writes landed. Reads back e32_vbase (off 0x08) from
       our patched header page and compares to the value we wrote
       (orig_vbase). Mismatch means DRAM write didn't take. */
    const uint32_t verify_vbase = mem.ReadWord(hdr_pa + kE32VbaseOff);
    if (verify_vbase != orig_vbase) {
        LOG(Caution, "[ImgfsInjector] %s VERIFY FAIL: hdr e32_vbase "
                "expected 0x%08X got 0x%08X\n",
                victim_name, orig_vbase, verify_vbase);
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

    /* Sections — each in its own fresh contiguous run of 4 KB pages.
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

    LOG(GuestAdditions,
        "[ImgfsInjector] %s injected: orig_vbase=0x%08X our_vbase=0x%08X "
        "slots=%zu hdr=%zu reloc_patched=%u\n",
        victim_name, orig_vbase, pe.ImageBase(),
        slots.size(), new_hdr.size(), reloc_count);
    return true;
}
