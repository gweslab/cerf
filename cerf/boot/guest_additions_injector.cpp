#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include "ce_image_relocator.h"
#include "imgfs_injector.h"
#include "pe_image.h"
#include "rom_parser_service.h"
#include "rom_placer.h"

#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../core/log.h"
#include "../core/service.h"
#include "../core/string_utils.h"
#include "../cpu/emulated_memory.h"
#include "../boards/page_table_builder.h"

#include <windows.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kPageMask = 0xFFFu;

struct E32RomLayout {
    uint32_t size;
    uint32_t off_objcnt;
    uint32_t off_imageflags;
    uint32_t off_entryrva;
    uint32_t off_vbase;
    uint32_t off_subsysmajor;
    uint32_t off_subsysminor;
    uint32_t off_stackmax;
    uint32_t off_vsize;
    uint32_t off_sect14rva;
    uint32_t off_sect14size;
    int32_t  off_timestamp;     /* absent on CE3 → negative */
    uint32_t off_unit;
    uint32_t off_subsys;
};

constexpr E32RomLayout kE32RomCE3 = {
    106,
    0x00, 0x02, 0x04, 0x08,
    0x0C, 0x0E, 0x10, 0x14,
    0x18, 0x1C,
    -1,
    0x20, 0x68,
};

constexpr E32RomLayout kE32RomCE5plus = {
    110,
    0x00, 0x02, 0x04, 0x08,
    0x0C, 0x0E, 0x10, 0x14,
    0x18, 0x1C,
    0x20,
    0x24, 0x6C,
};

/* e32_subsysmajor lies at +0x0C in BOTH CE3 and CE5+ layouts —
   safe to read before the layout decision is made. */
constexpr uint32_t kE32SubsysmajorOff = 0x0C;

constexpr uint32_t kRomHdrSize    = 84;
constexpr uint32_t kTocEntrySize  = 32;

constexpr uint32_t kO32RomSize    = 24;
constexpr uint32_t kO32OffVsize    = 0;
constexpr uint32_t kO32OffRva      = 4;
constexpr uint32_t kO32OffPsize    = 8;
constexpr uint32_t kO32OffDataptr  = 12;
constexpr uint32_t kO32OffRealaddr = 16;
constexpr uint32_t kO32OffFlags    = 20;

constexpr uint32_t kHdrRAMFreeOff    = 0x18;

constexpr uint32_t kTocOffNFileSize  = 0x0C;
constexpr uint32_t kTocOffE32Offset  = 0x14;
constexpr uint32_t kTocOffO32Offset  = 0x18;
constexpr uint32_t kTocOffLoadOffset = 0x1C;

constexpr int kE32UnitCount = 9;

uint32_t AlignPage(uint32_t pa) {
    return (pa + kPageMask) & ~kPageMask;
}

class GuestAdditionsInjector : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        return emu_.Get<DeviceConfig>().guest_additions;
    }

    void OnReady() override {
        emu_.Get<RomPlacer>();

        auto& parser = emu_.Get<RomParserService>();
        if (!parser.Ok()) {
            LOG(Caution, "parser not ready, skipping\n");
            return;
        }

        ce_major_ = DetectCeMajor();
        layout_   = (ce_major_ <= 3) ? &kE32RomCE3 : &kE32RomCE5plus;
        LOG(GuestAdditions, "CE major=%u; e32_rom layout=%s "
                  "(size=%u, ts_off=%d, unit_off=0x%X, subsys_off=0x%X)\n",
            ce_major_, (layout_ == &kE32RomCE3) ? "CE3" : "CE5+",
            layout_->size, layout_->off_timestamp,
            layout_->off_unit, layout_->off_subsys);

        const auto& subs = emu_.Get<DeviceConfig>().global_rom_substitutions;
        if (subs.empty()) {
            LOG(Caution, "guest_additions enabled but cerf.json "
                    "global_substitutions_inside_rom is empty\n");
            CerfFatalExit();
        }

        auto& imgfs = emu_.Get<ImgfsInjector>();
        int matched = 0;
        for (const auto& sub : subs) {
            const std::string source_path = GetCerfDir() + "ce_apps\\" + sub.second;
            if (Replace(sub.first.c_str(), source_path))         ++matched;
            if (imgfs.ReplaceVictim(sub.first.c_str(), source_path)) ++matched;
        }
        if (matched == 0) {
            LOG(Caution, "no display-driver victim matched\n");
            CerfFatalExit();
        }
        LOG(GuestAdditions, "%d victim(s) replaced\n", matched);
    }

private:
    bool Replace(const char* victim_name, const std::string& source_path);

    bool FindVictim(const char* name, size_t& out_index, uint32_t& out_entry_kva);
    uint32_t KvaForPa(uint32_t pa);
    static uint32_t SectionStepPa(uint32_t cursor, uint32_t psize) {
        return cursor + AlignPage(psize);
    }

    uint32_t DetectCeMajor();

    void     WriteE32Rom    (uint32_t pa, const PeImage& pe,
                              uint32_t target_vbase);
    void     WriteO32Array  (uint32_t pa, const PeImage& pe,
                              uint32_t section_pa_base,
                              uint32_t target_base,
                              uint32_t slot_base);
    uint32_t WriteSectionBytes(uint32_t pa, const PeImage& pe,
                                const std::vector<uint8_t>& bytes);

    uint32_t              ce_major_ = 5;
    const E32RomLayout*   layout_   = &kE32RomCE5plus;
};

uint32_t GuestAdditionsInjector::DetectCeMajor() {
    auto& parser = emu_.Get<RomParserService>();
    auto* nk = parser.KernelModule();
    if (!nk) {
        LOG(Caution, "nk.exe missing from TOC — can't "
                "read e32_subsysmajor and the kernel won't boot without "
                "nk anyway; refusing to guess e32_rom layout\n");
        CerfFatalExit();
    }
    auto& pt = emu_.Get<PageTableBuilder>();
    auto& mem = emu_.Get<EmulatedMemory>();
    const uint32_t e32_pa = pt.VaToPa(nk->ulE32Offset);
    const uint16_t subsysmajor = mem.ReadHalf(e32_pa + kE32SubsysmajorOff);
    if (subsysmajor < 3 || subsysmajor > 8) {
        LOG(Caution, "nk.exe e32_subsysmajor=%u outside "
                "plausible CE range (3..8) — refusing to guess e32_rom "
                "layout; injection would corrupt the kernel's view of "
                "the patched module\n", subsysmajor);
        CerfFatalExit();
    }
    return subsysmajor;
}

bool GuestAdditionsInjector::FindVictim(const char* name, size_t& out_index,
                                         uint32_t& out_entry_kva) {
    auto& parser = emu_.Get<RomParserService>();
    const auto& rom = parser.Primary();
    if (rom.xips.empty()) return false;
    const auto& toc = rom.xips[0].toc;
    for (size_t i = 0; i < toc.modules.size(); ++i) {
        if (_stricmp(toc.modules[i].lpszFileName.c_str(), name) == 0) {
            out_index     = i;
            out_entry_kva = toc.romhdr_va + kRomHdrSize
                          + uint32_t(i) * kTocEntrySize;
            return true;
        }
    }
    return false;
}

uint32_t GuestAdditionsInjector::KvaForPa(uint32_t pa) {
    auto& pt = emu_.Get<PageTableBuilder>();
    for (const auto& band : pt.CachedDramRegions()) {
        if (pa >= band.pa_base && pa < band.pa_base + band.size) {
            return band.va_base + (pa - band.pa_base);
        }
    }
    LOG(Caution, "PA 0x%08X falls outside every cached "
            "DRAM band; cannot compute kernel-VA\n", pa);
    return 0;
}

void GuestAdditionsInjector::WriteE32Rom(uint32_t pa, const PeImage& pe,
                                          uint32_t target_vbase) {
    auto& mem = emu_.Get<EmulatedMemory>();
    const E32RomLayout& L = *layout_;

    mem.WriteHalf(pa + L.off_objcnt,      uint16_t(pe.Sections().size()));
    mem.WriteHalf(pa + L.off_imageflags,  pe.ImageFlags());
    mem.WriteWord(pa + L.off_entryrva,    pe.EntryRva());
    mem.WriteWord(pa + L.off_vbase,       target_vbase);
    mem.WriteHalf(pa + L.off_subsysmajor, pe.SubsysMajor());
    mem.WriteHalf(pa + L.off_subsysminor, pe.SubsysMinor());
    mem.WriteWord(pa + L.off_stackmax,    pe.StackReserve());
    mem.WriteWord(pa + L.off_vsize,       pe.ImageSize());
    mem.WriteWord(pa + L.off_sect14rva,   0);
    mem.WriteWord(pa + L.off_sect14size,  0);
    if (L.off_timestamp >= 0) {
        mem.WriteWord(pa + uint32_t(L.off_timestamp), 0);
    }
    for (int i = 0; i < kE32UnitCount; ++i) {
        mem.WriteWord(pa + L.off_unit + uint32_t(i) * 8u + 0, pe.DirRva (i));
        mem.WriteWord(pa + L.off_unit + uint32_t(i) * 8u + 4, pe.DirSize(i));
    }
    mem.WriteHalf(pa + L.off_subsys,      pe.Subsystem());
}

void GuestAdditionsInjector::WriteO32Array(uint32_t pa, const PeImage& pe,
                                            uint32_t section_pa_base,
                                            uint32_t target_base,
                                            uint32_t slot_base) {
    auto& mem = emu_.Get<EmulatedMemory>();
    uint32_t section_pa = section_pa_base;
    for (size_t i = 0; i < pe.Sections().size(); ++i) {
        const auto& s = pe.Sections()[i];
        const uint32_t kva = KvaForPa(section_pa);
        const uint32_t off = pa + uint32_t(i) * kO32RomSize;

        const uint32_t realaddr = target_base + slot_base + s.rva;
        mem.WriteWord(off + kO32OffVsize,    s.vsize);
        mem.WriteWord(off + kO32OffRva,      s.rva);
        mem.WriteWord(off + kO32OffPsize,    s.psize);
        mem.WriteWord(off + kO32OffDataptr,  kva);
        mem.WriteWord(off + kO32OffRealaddr, realaddr);
        mem.WriteWord(off + kO32OffFlags,    s.flags);

        LOG(GuestAdditions, "  o32[%zu] vsize=0x%05X rva=0x%05X "
                  "psize=0x%05X dataptr=0x%08X realaddr=0x%08X flags=0x%08X\n",
            i, s.vsize, s.rva, s.psize, kva, realaddr, s.flags);

        section_pa = SectionStepPa(section_pa, s.psize);
    }
}

uint32_t GuestAdditionsInjector::WriteSectionBytes(uint32_t pa,
                                                    const PeImage& pe,
                                                    const std::vector<uint8_t>& bytes) {
    auto& mem = emu_.Get<EmulatedMemory>();

    uint32_t cursor = pa;
    for (const auto& s : pe.Sections()) {
        if (s.psize > 0 && size_t(s.pe_file_off) + s.psize <= bytes.size()) {
            mem.CopyIn(cursor, bytes.data() + s.pe_file_off, s.psize);
        }
        cursor = SectionStepPa(cursor, s.psize);
    }
    return cursor;
}

bool GuestAdditionsInjector::Replace(const char* victim_name,
                                       const std::string& source_path) {
    size_t   victim_idx = 0;
    uint32_t entry_kva  = 0;
    if (!FindVictim(victim_name, victim_idx, entry_kva)) {
        LOG(GuestAdditions, "'%s' not present in TOC — skip\n", victim_name);
        return false;
    }

    std::ifstream f(source_path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) {
        LOG(Caution, "cannot open %s — cerf_guest.dll "
                "must be built and staged before injecting %s\n",
                source_path.c_str(), victim_name);
        CerfFatalExit();
    }
    const auto sz = f.tellg();
    std::vector<uint8_t> pe_bytes(static_cast<size_t>(sz));
    f.seekg(0);
    f.read(reinterpret_cast<char*>(pe_bytes.data()), sz);
    const size_t pe_bytes_size = pe_bytes.size();

    PeImage pe(std::move(pe_bytes));
    if (!pe.Parsed()) {
        LOG(Caution, "PE parse failed for %s — "
                "cerf_guest.dll is corrupt; injection of %s aborted\n",
                source_path.c_str(), victim_name);
        CerfFatalExit();
    }

    auto& parser = emu_.Get<RomParserService>();
    const auto& rom = parser.Primary();
    if (rom.xips.empty()) {
        LOG(Caution, "primary ROM has no XIP regions — "
                "FindVictim matched %s but the TOC vanished by the time "
                "we tried to read it\n", victim_name);
        CerfFatalExit();
    }
    const auto& primary_toc = rom.xips[0].toc;
    auto& pt = emu_.Get<PageTableBuilder>();
    auto& mem = emu_.Get<EmulatedMemory>();
    const E32RomLayout& L = *layout_;

    /* Fields read here (vbase/imgflags/objcnt) all lie in the
       common prefix shared by CE3 and CE5+ layouts. */
    const uint32_t orig_e32_kva = primary_toc.modules[victim_idx].ulE32Offset;
    const uint32_t orig_e32_pa  = pt.VaToPa(orig_e32_kva);
    const uint32_t orig_o32_kva = primary_toc.modules[victim_idx].ulO32Offset;
    const uint32_t orig_o32_pa  = pt.VaToPa(orig_o32_kva);
    const uint32_t orig_vbase   = mem.ReadWord(orig_e32_pa + L.off_vbase);
    const uint16_t orig_imgflags = mem.ReadHalf(orig_e32_pa + L.off_imageflags);
    const uint16_t orig_objcnt  = mem.ReadHalf(orig_e32_pa + L.off_objcnt);
    LOG(GuestAdditions, "orig %s e32 @KVA 0x%08X imageflags=0x%04X "
              "objcnt=%u o32 @KVA 0x%08X\n",
        victim_name, orig_e32_kva, orig_imgflags, orig_objcnt, orig_o32_kva);
    for (uint32_t i = 0; i < orig_objcnt && i < 16; ++i) {
        const uint32_t off = orig_o32_pa + i * kO32RomSize;
        LOG(GuestAdditions, "  ORIG o32[%u] vsize=0x%05X rva=0x%05X psize=0x%05X "
                  "dataptr=0x%08X realaddr=0x%08X flags=0x%08X\n",
            i,
            mem.ReadWord(off + kO32OffVsize),
            mem.ReadWord(off + kO32OffRva),
            mem.ReadWord(off + kO32OffPsize),
            mem.ReadWord(off + kO32OffDataptr),
            mem.ReadWord(off + kO32OffRealaddr),
            mem.ReadWord(off + kO32OffFlags));
    }
    bool vbase_ok = false;
    if (ce_major_ >= 6) {
        const uint32_t um_first = (primary_toc.romhdr.dllfirst >> 16) << 16;
        const uint32_t um_last  = (primary_toc.romhdr.dlllast  >> 16) << 16;
        const uint32_t km_first = (primary_toc.romhdr.dllfirst & 0xFFFFu) << 16;
        const uint32_t km_last  = (primary_toc.romhdr.dlllast  & 0xFFFFu) << 16;
        vbase_ok = (orig_vbase >= um_first && orig_vbase < um_last)
                || (orig_vbase >= km_first && orig_vbase < km_last);
        LOG(GuestAdditions, "CE6+ slot decode: user=0x%08X..0x%08X "
                  "kernel=0x%08X..0x%08X (raw dllfirst=0x%08X dlllast=0x%08X)\n",
            um_first, um_last, km_first, km_last,
            primary_toc.romhdr.dllfirst, primary_toc.romhdr.dlllast);
    } else {
        /* Need BOTH clauses. DO NOT drop in_dll_region for xip_codebase alone:
           CE3 ddi.dll has vbase 0x01680000 != codebase 0x03680000 (code realaddr
           in slot 1) so xip_codebase REJECTS it -> CE3 GA FATALs. xip_codebase
           covers kernel-fixup DLLs whose code XIPs above dlllast (CE5/Zune). */
        const uint32_t code_realaddr0 =
            mem.ReadWord(orig_o32_pa + kO32OffRealaddr);
        const uint32_t code_rva0 =
            mem.ReadWord(orig_o32_pa + kO32OffRva);
        const uint32_t codebase = code_realaddr0 - code_rva0;
        const bool in_dll_region = (orig_vbase >= primary_toc.romhdr.dllfirst)
                                && (orig_vbase <  primary_toc.romhdr.dlllast);
        /* < physfirst: a fixed-up driver's runtime code VA is a low slot
           address, never in the ROM/kernel image region — keeps a garbage
           page-aligned vbase that coincidentally equals codebase out. */
        const bool xip_codebase  = (orig_objcnt > 0) && (orig_vbase != 0)
                                && ((orig_vbase & kPageMask) == 0)
                                && (orig_vbase == codebase)
                                && (orig_vbase < primary_toc.romhdr.physfirst);
        vbase_ok = in_dll_region || xip_codebase;
        LOG(GuestAdditions, "CE<6 vbase check: vbase=0x%08X codebase=0x%08X "
                  "(o32[0] realaddr=0x%08X rva=0x%08X) dllfirst=0x%08X "
                  "dlllast=0x%08X in_dll=%d xip=%d -> %s\n",
            orig_vbase, codebase, code_realaddr0, code_rva0,
            primary_toc.romhdr.dllfirst, primary_toc.romhdr.dlllast,
            in_dll_region, xip_codebase, vbase_ok ? "ok" : "REJECT");
    }
    if (!vbase_ok) {
        LOG(Caution, "%s original vbase 0x%08X fails sanity "
                "(CE major=%u, objcnt=%u, raw dllfirst=0x%08X dlllast=0x%08X) "
                "— e32_vbase does not match o32[0] codebase / unaligned / "
                "zero; probable ROMHDR corruption or unsupported CE version\n",
            victim_name, orig_vbase, ce_major_, orig_objcnt,
            primary_toc.romhdr.dllfirst, primary_toc.romhdr.dlllast);
        CerfFatalExit();
    }

    /* MUST anchor past ulRAMFree — `[ulRAMStart, ulRAMFree)` is NK's
       live RW workspace; bytes placed inside it get clobbered when
       NK writes its globals mid-boot. */
    const uint32_t orig_ramfree_va = primary_toc.romhdr.ulRAMFree;
    const uint32_t orig_ramfree_pa = pt.VaToPa(orig_ramfree_va);

    const uint32_t e32_pa = AlignPage(orig_ramfree_pa);
    const uint32_t o32_pa = e32_pa + AlignPage(L.size);
    const uint32_t section_pa_base =
        o32_pa + AlignPage(uint32_t(pe.Sections().size()) * kO32RomSize);

    const uint32_t e32_kva = KvaForPa(e32_pa);
    const uint32_t o32_kva = KvaForPa(o32_pa);
    const uint32_t section_kva_base = KvaForPa(section_pa_base);
    if (!e32_kva || !o32_kva || !section_kva_base) {
        LOG(Caution, "appended region does not fit "
                "inside any cached-DRAM band (e32_pa=0x%08X o32_pa=0x%08X "
                "section_pa=0x%08X) — the injected e32/o32/sections have "
                "no kernel-VA the kernel can dereference\n",
            e32_pa, o32_pa, section_pa_base);
        CerfFatalExit();
    }

    std::vector<uint8_t> patched_bytes(pe.Bytes().begin(), pe.Bytes().end());
    const int32_t delta =
        int32_t(orig_vbase) - int32_t(pe.ImageBase());
    uint32_t reloc_count = 0;
    uint32_t unhandled_relocs = 0;
    cerf::ce_image_relocator::ApplyRelocations(
        patched_bytes, pe, delta, reloc_count, unhandled_relocs);
    LOG(GuestAdditions, "%s reloc delta=0x%08X patched=%u unhandled=%u\n",
        victim_name, uint32_t(delta), reloc_count, unhandled_relocs);
    if (unhandled_relocs > 0) {
        LOG(Caution, "%s has %u unhandled relocation "
                "entries (likely ARM_MOV32/THUMB_MOV32). The injected "
                "DLL would jump to unrelocated addresses on first use; "
                "rebuild cerf_guest with /machine:THUMB ARMV4I (no "
                "MOVW/MOVT) or extend ce_image_relocator to handle the "
                "missing types.\n", victim_name, unhandled_relocs);
        CerfFatalExit();
    }

    uint32_t slot_base = 0;
    if (orig_objcnt > 0) {
        const uint32_t orig_realaddr0 =
            mem.ReadWord(orig_o32_pa + 0 * kO32RomSize + kO32OffRealaddr);
        const uint32_t orig_rva0 =
            mem.ReadWord(orig_o32_pa + 0 * kO32RomSize + kO32OffRva);
        slot_base = orig_realaddr0 - orig_rva0 - orig_vbase;
        LOG(GuestAdditions, "derived slot_base=0x%08X "
                  "(from orig realaddr=0x%08X rva=0x%08X vbase=0x%08X)\n",
            slot_base, orig_realaddr0, orig_rva0, orig_vbase);
    }

    WriteE32Rom  (e32_pa, pe, orig_vbase);
    WriteO32Array(o32_pa, pe, section_pa_base, orig_vbase, slot_base);
    const uint32_t after_sections_pa =
        WriteSectionBytes(section_pa_base, pe, patched_bytes);


    const uint32_t entry_pa = pt.VaToPa(entry_kva);
    mem.WriteWord(entry_pa + kTocOffNFileSize,  uint32_t(pe_bytes_size));
    mem.WriteWord(entry_pa + kTocOffE32Offset,  e32_kva);
    mem.WriteWord(entry_pa + kTocOffO32Offset,  o32_kva);
    mem.WriteWord(entry_pa + kTocOffLoadOffset, section_kva_base);

    const uint32_t new_ramfree_pa = AlignPage(after_sections_pa);
    const uint32_t new_ramfree_va = KvaForPa(new_ramfree_pa);

    const uint32_t romhdr_pa = pt.VaToPa(primary_toc.romhdr_va);
    mem.WriteWord(romhdr_pa + kHdrRAMFreeOff, new_ramfree_va);

    LOG(GuestAdditions, "%s slot redirected: idx=%zu entry_kva=0x%08X "
              "e32_kva=0x%08X o32_kva=0x%08X load_kva=0x%08X "
              "sections=%zu pe_size=%zu orig_vbase=0x%08X our_vbase=0x%08X\n",
        victim_name, victim_idx, entry_kva, e32_kva, o32_kva,
        section_kva_base, pe.Sections().size(), pe_bytes_size,
        orig_vbase, pe.ImageBase());
    LOG(GuestAdditions, "ROMHDR ulRAMFree 0x%08X -> 0x%08X "
              "(physlast 0x%08X / ulRAMStart 0x%08X unchanged)\n",
        orig_ramfree_va, new_ramfree_va,
        primary_toc.romhdr.physlast, primary_toc.romhdr.ulRAMStart);
    return true;
}

}

REGISTER_SERVICE(GuestAdditionsInjector);
