#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include "ce_image_relocator.h"
#include "ce_import_binder.h"
#include "cerf_injection_region.h"
#include "guest_additions_binaries.h"
#include "guest_cold_boot.h"
#include "guest_module_placer.h"
#include "imgfs_injector.h"
#include "pe_image.h"
#include "rom_parser_queries.h"
#include "rom_parser_service.h"
#include "rom_placer.h"

#include "../boards/board_context.h"
#include "rom_record_layout.h"

#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../core/log.h"
#include "../core/service.h"
#include "../cpu/emulated_memory.h"
#include "../boards/page_table_builder.h"
#include "../socs/guest_cpu_reset.h"

#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kPageMask = 0xFFFu;

constexpr uint32_t kImgScnMemShared = 0x10000000u;
constexpr uint32_t kImgScnMemWrite  = 0x80000000u;

uint32_t AlignPage(uint32_t v) { return (v + kPageMask) & ~kPageMask; }
uint32_t Align4(uint32_t v)    { return (v + 3u) & ~3u; }

class GuestAdditionsInjector : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        return emu_.Get<DeviceConfig>().guest_additions
            && emu_.Get<BoardContext>().GetRomPlacingMode()
                   == RomPlacingMode::FlatContainer;
    }

    void OnReady() override {
        emu_.Get<RomPlacer>();

        auto& parser = emu_.Get<RomParserService>();
        if (!parser.Ok()) {
            LOG(Caution, "parser not ready, skipping\n");
            return;
        }

        ce_major_ = DetectCeMajor();
        layout_ = (ce_major_ <= 2 && ce_minor_ < 11) ? &kE32RomCE20
                : (ce_major_ <= 2)                   ? &kE32RomCE211
                : (ce_major_ <= 4)                   ? &kE32RomCE3
                                                     : &kE32RomCE5plus;
        const char* layout_name = (layout_ == &kE32RomCE20)  ? "CE2.0"
                                : (layout_ == &kE32RomCE211) ? "CE2.11"
                                : (layout_ == &kE32RomCE3)   ? "pre-CE5"
                                                             : "CE5+";
        LOG(GuestAdditions, "CE version=%u.%u; e32_rom layout=%s\n",
            ce_major_, ce_minor_, layout_name);

        const auto& victims = emu_.Get<DeviceConfig>().guest_additions_victims;
        if (victims.empty()) {
            LOG(Caution, "guest_additions enabled but cerf.json "
                    "video_driver_names_for_guest_additions is empty\n");
            CerfFatalExit();
        }

        const std::string stub_path =
            emu_.Get<GuestAdditionsBinaries>().StubPath();

        auto& imgfs = emu_.Get<ImgfsInjector>();
        int matched = 0;
        for (const auto& victim : victims) {
            /* IMGFS injects the SAME stub, not the full body: a kernel-loaded
               full body shares one .data across gwes + the device.exe carrier at
               the high victim vbase (the CE5 loader doesn't per-process it) and
               corrupts gwes's globals; the stub manual-maps the body per-process. */
            if (Replace(victim.c_str(), stub_path)) ++matched;
            if (imgfs.ReplaceVictim(victim.c_str(), stub_path)) ++matched;
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
    uint32_t DetectCeMajor();

    void WriteE32Rom(uint32_t pa, const PeImage& pe, uint32_t target_vbase,
                     uint16_t subsys_major, uint16_t subsys_minor);
    void WriteO32Array(uint32_t pa, const PeImage& pe,
                       const std::vector<uint32_t>& dataptr_kva,
                       const std::vector<uint32_t>& realaddr,
                       const std::vector<uint32_t>& flags);
    void WriteSectionBytes(const std::vector<uint32_t>& sec_pa, const PeImage& pe,
                           const std::vector<uint8_t>& bytes);

    uint32_t            ce_major_ = 5;
    uint32_t            ce_minor_ = 0;
    const E32RomLayout* layout_   = &kE32RomCE5plus;
};

uint32_t GuestAdditionsInjector::DetectCeMajor() {
    uint16_t major = 0, minor = 0;
    if (!emu_.Get<RomParserQueries>().KernelSubsystemVersion(major, minor)) {
        LOG(Caution, "nk.exe e32_rom subsystem version not locatable\n");
        CerfFatalExit();
    }
    if (major < 2 || major > 8) {
        LOG(Caution, "nk.exe e32_subsysmajor=%u outside CE range 2..8\n", major);
        CerfFatalExit();
    }
    ce_minor_ = minor;
    return major;
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

void GuestAdditionsInjector::WriteE32Rom(uint32_t pa, const PeImage& pe,
                                          uint32_t target_vbase,
                                          uint16_t subsys_major,
                                          uint16_t subsys_minor) {
    auto& mem = emu_.Get<EmulatedMemory>();
    const E32RomLayout& L = *layout_;

    mem.WriteHalf(pa + L.off_objcnt,      uint16_t(pe.Sections().size()));
    mem.WriteHalf(pa + L.off_imageflags,  pe.ImageFlags());
    mem.WriteWord(pa + L.off_entryrva,    pe.EntryRva());
    mem.WriteWord(pa + L.off_vbase,       target_vbase);
    mem.WriteHalf(pa + L.off_subsysmajor, subsys_major);
    mem.WriteHalf(pa + L.off_subsysminor, subsys_minor);
    if (L.off_stackmax >= 0) {
        mem.WriteWord(pa + uint32_t(L.off_stackmax), pe.StackReserve());
    }
    if (L.off_vsize >= 0) {
        mem.WriteWord(pa + uint32_t(L.off_vsize), pe.ImageSize());
    }
    if (L.off_sect14rva >= 0) {
        mem.WriteWord(pa + uint32_t(L.off_sect14rva),  0);
    }
    if (L.off_sect14size >= 0) {
        mem.WriteWord(pa + uint32_t(L.off_sect14size), 0);
    }
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
                                            const std::vector<uint32_t>& dataptr_kva,
                                            const std::vector<uint32_t>& realaddr,
                                            const std::vector<uint32_t>& flags) {
    auto& mem = emu_.Get<EmulatedMemory>();
    for (size_t i = 0; i < pe.Sections().size(); ++i) {
        const auto& s = pe.Sections()[i];
        const uint32_t off = pa + uint32_t(i) * kO32RomSize;
        mem.WriteWord(off + kO32OffVsize,    s.vsize);
        mem.WriteWord(off + kO32OffRva,      s.rva);
        mem.WriteWord(off + kO32OffPsize,    s.psize);
        mem.WriteWord(off + kO32OffDataptr,  dataptr_kva[i]);
        mem.WriteWord(off + kO32OffRealaddr, realaddr[i]);
        mem.WriteWord(off + kO32OffFlags,    flags[i]);
        LOG(GuestAdditions, "  o32[%zu] vsize=0x%05X rva=0x%05X psize=0x%05X "
                  "dataptr=0x%08X realaddr=0x%08X flags=0x%08X\n",
            i, s.vsize, s.rva, s.psize, dataptr_kva[i], realaddr[i], flags[i]);
    }
}

void GuestAdditionsInjector::WriteSectionBytes(const std::vector<uint32_t>& sec_pa,
                                                const PeImage& pe,
                                                const std::vector<uint8_t>& bytes) {
    auto& mem = emu_.Get<EmulatedMemory>();
    for (size_t i = 0; i < pe.Sections().size(); ++i) {
        const auto& s = pe.Sections()[i];
        if (s.psize > 0 && size_t(s.pe_file_off) + s.psize <= bytes.size()) {
            mem.CopyIn(sec_pa[i], bytes.data() + s.pe_file_off, s.psize);
        }
    }
}

bool GuestAdditionsInjector::Replace(const char* victim_name,
                                      const std::string& source_path) {
    size_t   victim_idx = 0;
    uint32_t entry_kva  = 0;
    if (!FindVictim(victim_name, victim_idx, entry_kva)) {
        LOG(GuestAdditions, "'%s' not present in TOC - skip\n", victim_name);
        return false;
    }

    std::ifstream f(source_path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) {
        LOG(Caution, "cannot open %s - cerf_guest_stub.dll must be built and "
                "staged before injecting %s\n", source_path.c_str(), victim_name);
        CerfFatalExit();
    }
    const auto sz = f.tellg();
    std::vector<uint8_t> pe_bytes(static_cast<size_t>(sz));
    f.seekg(0);
    f.read(reinterpret_cast<char*>(pe_bytes.data()), sz);
    const size_t pe_bytes_size = pe_bytes.size();

    PeImage pe(std::move(pe_bytes));
    if (!pe.Parsed()) {
        LOG(Caution, "PE parse failed for %s - stub is corrupt; injection of "
                "%s aborted\n", source_path.c_str(), victim_name);
        CerfFatalExit();
    }

    auto& parser = emu_.Get<RomParserService>();
    const auto& rom = parser.Primary();
    if (rom.xips.empty()) {
        LOG(Caution, "primary ROM has no XIP regions - FindVictim matched %s "
                "but the TOC vanished\n", victim_name);
        CerfFatalExit();
    }
    const auto& primary_toc = rom.xips[0].toc;
    auto& pt  = emu_.Get<PageTableBuilder>();
    auto& mem = emu_.Get<EmulatedMemory>();
    const E32RomLayout& L = *layout_;

    const uint32_t orig_e32_kva  = primary_toc.modules[victim_idx].ulE32Offset;
    const uint32_t orig_e32_pa   = pt.VaToPa(orig_e32_kva);
    const uint32_t orig_o32_kva  = primary_toc.modules[victim_idx].ulO32Offset;
    const uint32_t orig_o32_pa   = pt.VaToPa(orig_o32_kva);
    const uint32_t orig_vbase    = mem.ReadWord(orig_e32_pa + L.off_vbase);
    const uint16_t orig_imgflags = mem.ReadHalf(orig_e32_pa + L.off_imageflags);
    const uint16_t orig_objcnt   = mem.ReadHalf(orig_e32_pa + L.off_objcnt);
    const uint16_t orig_subsysmaj = mem.ReadHalf(orig_e32_pa + L.off_subsysmajor);
    const uint16_t orig_subsysmin = mem.ReadHalf(orig_e32_pa + L.off_subsysminor);
    if (orig_objcnt == 0) {
        LOG(Caution, "%s victim has zero sections - no footprint to reuse for "
                "the stub\n", victim_name);
        CerfFatalExit();
    }
    LOG(GuestAdditions, "orig %s e32 @KVA 0x%08X imageflags=0x%04X objcnt=%u "
              "subsysver=%u.%02u o32 @KVA 0x%08X\n",
        victim_name, orig_e32_kva, orig_imgflags, orig_objcnt,
        orig_subsysmaj, orig_subsysmin, orig_o32_kva);
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

    const uint32_t code_realaddr0 = mem.ReadWord(orig_o32_pa + kO32OffRealaddr);
    const uint32_t code_rva0      = mem.ReadWord(orig_o32_pa + kO32OffRva);
    const uint32_t codebase       = code_realaddr0 - code_rva0;

    bool vbase_ok = false;
    if (ce_major_ >= 6) {
        const uint32_t um_first = (primary_toc.romhdr.dllfirst >> 16) << 16;
        const uint32_t um_last  = (primary_toc.romhdr.dlllast  >> 16) << 16;
        const uint32_t km_first = (primary_toc.romhdr.dllfirst & 0xFFFFu) << 16;
        const uint32_t km_last  = (primary_toc.romhdr.dlllast  & 0xFFFFu) << 16;
        vbase_ok = (orig_vbase >= um_first && orig_vbase < um_last)
                || (orig_vbase >= km_first && orig_vbase < km_last);
    } else {
        const bool in_dll_region = (orig_vbase >= primary_toc.romhdr.dllfirst)
                                && (orig_vbase <  primary_toc.romhdr.dlllast);
        const bool xip_codebase  = (orig_vbase != 0)
                                && ((orig_vbase & kPageMask) == 0)
                                && (orig_vbase == codebase)
                                && (orig_vbase < primary_toc.romhdr.physfirst);
        vbase_ok = in_dll_region || xip_codebase;
    }
    if (!vbase_ok) {
        LOG(Caution, "%s original vbase 0x%08X fails sanity (CE major=%u, "
                "codebase=0x%08X, dllfirst=0x%08X dlllast=0x%08X) - probable "
                "ROMHDR corruption or unsupported CE version\n",
            victim_name, orig_vbase, ce_major_, codebase,
            primary_toc.romhdr.dllfirst, primary_toc.romhdr.dlllast);
        CerfFatalExit();
    }

    /* Acquire the CERF-owned injection band (lazy; halts if this board's OAT
       leaves no static-window hole). The stub's records + section bytes live
       here, never the victim's section; the TOC is repointed at band VAs the
       MMU walker overlay serves. */
    auto& region = emu_.Get<CerfInjectionRegion>();
    const uint32_t band_va   = region.BandVaBase();
    const uint32_t band_pa   = region.BandPaBase();
    const uint32_t band_size = region.BandSize();

    const bool in_place = (ce_major_ >= 6);

    uint32_t target_vbase = band_va;
    uint32_t run_base     = band_va;   /* base the section bytes are relocated for */
    if (!in_place) {
        const uint32_t slot_base = codebase - orig_vbase;
        target_vbase = emu_.Get<GuestModulePlacer>().ComputeVbase(
            orig_vbase, slot_base, pe.ImageSize(), ce_major_, L.off_vbase,
            victim_name);
        run_base = target_vbase + slot_base;
    }

    /* RVA layout in the band: section i bytes at band+rva, so an in-place
       module runs correctly at vbase=band_va with section i at band_va+rva.
       dataptr is always the band VA (overlay-served source). */
    const size_t nsec = pe.Sections().size();
    std::vector<uint32_t> sec_pa(nsec), dataptr(nsec), realaddr(nsec), flags(nsec);
    for (size_t i = 0; i < nsec; ++i) {
        const auto& s = pe.Sections()[i];
        sec_pa[i]   = band_pa + s.rva;
        dataptr[i]  = band_va + s.rva;
        realaddr[i] = run_base + s.rva;
        flags[i] = in_place
            ? emu_.Get<GuestModulePlacer>().EffSectionFlags(s.flags)
            : (s.flags | kImgScnMemWrite | kImgScnMemShared);
    }

    /* Records after the full virtual image (overlay-served reads of e32/o32). */
    const uint32_t e32_va    = band_va + AlignPage(pe.ImageSize());
    const uint32_t o32_va    = Align4(e32_va + L.size);
    const uint32_t band_used = (o32_va + uint32_t(nsec) * kO32RomSize) - band_va;
    if (band_used > band_size) {
        LOG(Caution, "%s stub needs 0x%X band bytes but the band is 0x%X - raise "
                "kInjectionBandSize in cerf_virt_addr_map.h\n",
            victim_name, band_used, band_size);
        CerfFatalExit();
    }

    std::vector<uint8_t> patched_bytes(pe.Bytes().begin(), pe.Bytes().end());
    const int32_t code_delta = int32_t(run_base) - int32_t(pe.ImageBase());
    uint32_t reloc_count = 0;
    uint32_t unhandled_relocs = 0;
    cerf::ce_image_relocator::ApplyRelocations(
        patched_bytes, pe, realaddr, code_delta, reloc_count, unhandled_relocs);
    LOG(GuestAdditions, "%s reloc code_delta=0x%08X patched=%u unhandled=%u\n",
        victim_name, uint32_t(code_delta), reloc_count, unhandled_relocs);
    if (unhandled_relocs > 0) {
        LOG(Caution, "%s has %u unhandled relocation entries (likely "
                "ARM_MOV32/THUMB_MOV32) - the stub would jump to unrelocated "
                "addresses; rebuild it without MOVW/MOVT or extend "
                "ce_image_relocator\n", victim_name, unhandled_relocs);
        CerfFatalExit();
    }

    emu_.Get<GuestAdditionsBinaries>().StampWindowBase(patched_bytes);

    /* Only CE2.11 needs this: it does not bind an injected ROM module's imports
       (CE3+ kernels rebind at load). Restricting to CE2 also avoids reading CE3+
       coredll, whose ROM sections may be compressed (garbage at injection time). */
    if (ce_major_ <= 2) {
        emu_.Get<CeImportBinder>().BindImports(patched_bytes, pe, L);
    }

    const uint32_t e32_pa = band_pa + (e32_va - band_va);
    const uint32_t o32_pa = band_pa + (o32_va - band_va);
    WriteE32Rom(e32_pa, pe, target_vbase, orig_subsysmaj, orig_subsysmin);
    WriteO32Array(o32_pa, pe, dataptr, realaddr, flags);
    WriteSectionBytes(sec_pa, pe, patched_bytes);

    const uint32_t entry_pa = pt.VaToPa(entry_kva);
    mem.WriteWord(entry_pa + kTocOffNFileSize,  uint32_t(pe_bytes_size));
    mem.WriteWord(entry_pa + kTocOffE32Offset,  e32_va);
    mem.WriteWord(entry_pa + kTocOffO32Offset,  o32_va);
    mem.WriteWord(entry_pa + kTocOffLoadOffset, band_va);

    LOG(GuestAdditions, "%s stub injected (%s): idx=%zu entry_kva=0x%08X "
              "band VA=0x%08X PA=0x%08X e32=0x%08X o32=0x%08X sections=%zu "
              "vbase=0x%08X run_base=0x%08X\n",
        victim_name, in_place ? "in-place" : "copy", victim_idx, entry_kva,
        band_va, band_pa, e32_va, o32_va, nsec, target_vbase, run_base);

    /* The band PA region is volatile (cerf_virt window) and a RAMIMAGE board's
       TOC-entry span is volatile - replay the band writes + the TOCentry repoint
       so a cold boot restores them. */
    auto& coldboot = emu_.Get<GuestColdBoot>();
    for (size_t i = 0; i < nsec; ++i) {
        const auto& s = pe.Sections()[i];
        if (s.psize > 0 && size_t(s.pe_file_off) + s.psize <= patched_bytes.size()) {
            coldboot.RecordPatch(sec_pa[i], s.psize);
        }
    }
    coldboot.RecordPatch(e32_pa, L.size);
    coldboot.RecordPatch(o32_pa, uint32_t(nsec) * kO32RomSize);
    coldboot.RecordPatch(entry_pa + kTocOffNFileSize,  4);
    coldboot.RecordPatch(entry_pa + kTocOffE32Offset,  4);
    coldboot.RecordPatch(entry_pa + kTocOffO32Offset,  4);
    coldboot.RecordPatch(entry_pa + kTocOffLoadOffset, 4);
    /* ComputeVbase may have lowered ROMHDR.dllfirst (DllLoadBase) for a
       relocated section-1 vbase; replay it on hard reset. */
    if (!in_place) {
        coldboot.RecordPatch(pt.VaToPa(primary_toc.romhdr_va) + kHdrDllFirstOff, 4);
    }

    /* In-place stubs mutate their writable .data in the band; a warm reset neither
       re-copies the section (in-place skips ReadSection) nor replays the band
       (cold-boot only), so without this the post-reset stub reads stale prior-boot
       pointers and faults. Restore the band's initial bytes on each reset. */
    if (in_place) {
        std::vector<uint8_t> band_initial(band_used);
        mem.CopyOut(band_pa, band_initial.data(), band_used);
        emu_.Get<GuestCpuReset>().RegisterResetListener(
            [this, band_pa, band_initial = std::move(band_initial)](ResetLineKind) {
                emu_.Get<EmulatedMemory>().CopyIn(band_pa, band_initial.data(),
                                                  band_initial.size());
            });
    }
    return true;
}

}  /* namespace */

REGISTER_SERVICE(GuestAdditionsInjector);
