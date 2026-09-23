#include "ce_import_binder.h"

#include "pe_image.h"
#include "rom_parser_service.h"

#include "../core/ascii_z.h"
#include "../core/byte_order.h"
#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "../cpu/emulated_memory.h"
#include "../boards/page_table_builder.h"

#include <cstring>
#include <string>

REGISTER_SERVICE(CeImportBinder);

namespace {

/* PE/COFF on-disk layout (Microsoft PE/COFF spec). */
constexpr uint32_t kOrdinalFlag32  = 0x80000000u;   /* IMAGE_ORDINAL_FLAG32 */
constexpr uint32_t kImportDescSize = 20u;           /* IMAGE_IMPORT_DESCRIPTOR */
constexpr uint32_t kImpOffOft      = 0u;            /* OriginalFirstThunk */
constexpr uint32_t kImpOffName     = 12u;           /* Name (rva)         */
constexpr uint32_t kImpOffFt       = 16u;           /* FirstThunk (IAT)   */

/* IMAGE_EXPORT_DIRECTORY field offsets. */
constexpr uint32_t kExpOffBase      = 16u;          /* Base (ordinal base)   */
constexpr uint32_t kExpOffNumFuncs  = 20u;          /* NumberOfFunctions     */
constexpr uint32_t kExpOffNumNames  = 24u;          /* NumberOfNames         */
constexpr uint32_t kExpOffAddrFuncs = 28u;          /* AddressOfFunctions    */
constexpr uint32_t kExpOffAddrNames = 32u;          /* AddressOfNames        */
constexpr uint32_t kExpOffAddrOrds  = 36u;          /* AddressOfNameOrdinals */

constexpr uint32_t kNoFileOff = PeImage::kNoFileOff;

using cerf::le::Put32;
using cerf::le::U32;


const ParsedTOCentry* FindRomModule(const ParsedRom& rom, const char* name) {
    for (const auto& xip : rom.xips)
        for (const auto& m : xip.toc.modules)
            if (_stricmp(m.lpszFileName.c_str(), name) == 0) return &m;
    return nullptr;
}

}  /* namespace */

void CeImportBinder::BindImports(std::vector<uint8_t>& bytes, const PeImage& pe,
                                 const E32RomLayout& layout) {
    const uint32_t imp_rva  = pe.DirRva(PeImage::kDirImport);
    const uint32_t imp_size = pe.DirSize(PeImage::kDirImport);
    if (imp_rva == 0 || imp_size == 0) return;

    /* Descriptors / OFT / names are RVAs the loader never relocates, so read them
       from the pristine PE; only the IAT (FirstThunk) is patched into `bytes`. */
    const std::vector<uint8_t>& src = pe.Bytes();
    uint32_t bound = 0;

    for (uint32_t d = imp_rva; ; d += kImportDescSize) {
        const uint32_t doff = pe.RvaToFileOff(d);
        if (doff == kNoFileOff || size_t(doff) + kImportDescSize > src.size()) {
            LOG(Caution, "CeImportBinder: import descriptor rva 0x%X out of image\n", d);
            CerfFatalExit();
        }
        const uint32_t oft_rva  = U32(src.data(),doff + kImpOffOft);
        const uint32_t name_rva = U32(src.data(),doff + kImpOffName);
        const uint32_t ft_rva   = U32(src.data(),doff + kImpOffFt);
        if (name_rva == 0 && ft_rva == 0) break;   /* null-terminator descriptor */

        const uint32_t noff = pe.RvaToFileOff(name_rva);
        if (noff == kNoFileOff) {
            LOG(Caution, "CeImportBinder: import DLL-name rva 0x%X out of image\n", name_rva);
            CerfFatalExit();
        }
        const std::string dll = cerf::ReadAsciiZ(src,noff);
        const GuestExportDir ed = LocateModuleExports(dll.c_str(), layout);

        const uint32_t thunk_rva = oft_rva ? oft_rva : ft_rva;
        for (uint32_t i = 0; ; ++i) {
            const uint32_t toff = pe.RvaToFileOff(thunk_rva + i * 4u);
            const uint32_t foff = pe.RvaToFileOff(ft_rva + i * 4u);
            if (toff == kNoFileOff || size_t(toff) + 4 > src.size()
                || foff == kNoFileOff || size_t(foff) + 4 > bytes.size()) {
                LOG(Caution, "CeImportBinder: thunk rva out of image (%s)\n", dll.c_str());
                CerfFatalExit();
            }
            const uint32_t orig = U32(src.data(),toff);
            if (orig == 0) break;   /* end of this DLL's thunk list */

            uint32_t resolved;
            if (orig & kOrdinalFlag32) {
                resolved = ResolveOrdinal(ed, orig & 0xFFFFu, dll.c_str());
            } else {
                const uint32_t inoff = pe.RvaToFileOff(orig + 2u);
                if (inoff == kNoFileOff) {
                    LOG(Caution, "CeImportBinder: import-by-name rva 0x%X out of image\n", orig);
                    CerfFatalExit();
                }
                resolved = ResolveName(ed, cerf::ReadAsciiZ(src,inoff).c_str(), dll.c_str());
            }
            Put32(bytes.data() + foff, resolved);
            ++bound;
        }
    }
    LOG(GuestAdditions, "CeImportBinder: pre-bound %u import(s)\n", bound);
}

CeImportBinder::GuestExportDir
CeImportBinder::LocateModuleExports(const char* dll, const E32RomLayout& layout) {
    const ParsedTOCentry* m =
        FindRomModule(emu_.Get<RomParserService>().Primary(), dll);
    if (!m) {
        LOG(Caution, "CeImportBinder: imported DLL '%s' not in ROM TOC\n", dll);
        CerfFatalExit();
    }
    auto& pt  = emu_.Get<PageTableBuilder>();
    auto& mem = emu_.Get<EmulatedMemory>();
    const uint32_t e32_pa = pt.VaToPa(m->ulE32Offset);

    GuestExportDir ed;
    ed.vbase    = mem.ReadWord(e32_pa + layout.off_vbase);
    ed.exp_rva  = mem.ReadWord(e32_pa + layout.off_unit + 0u);   /* e32_unit[EXP].rva  */
    ed.exp_size = mem.ReadWord(e32_pa + layout.off_unit + 4u);   /* e32_unit[EXP].size */
    ed.objcnt   = mem.ReadHalf(e32_pa + layout.off_objcnt);
    ed.o32_pa   = pt.VaToPa(m->ulO32Offset);
    if (ed.exp_rva == 0) {
        LOG(Caution, "CeImportBinder: '%s' has no export directory\n", dll);
        CerfFatalExit();
    }
    return ed;
}

uint32_t CeImportBinder::MapRvaToPa(const GuestExportDir& ed, uint32_t rva) {
    auto& pt  = emu_.Get<PageTableBuilder>();
    auto& mem = emu_.Get<EmulatedMemory>();
    for (uint32_t i = 0; i < ed.objcnt; ++i) {
        const uint32_t o    = ed.o32_pa + i * kO32RomSize;
        const uint32_t srva = mem.ReadWord(o + kO32OffRva);
        const uint32_t vsz  = mem.ReadWord(o + kO32OffVsize);
        if (rva >= srva && rva < srva + vsz) {
            const uint32_t dataptr = mem.ReadWord(o + kO32OffDataptr);
            return pt.VaToPa(dataptr + (rva - srva));
        }
    }
    LOG(Caution, "CeImportBinder: rva 0x%X not in any section\n", rva);
    CerfFatalExit();
}

uint32_t CeImportBinder::ResolveOrdinal(const GuestExportDir& ed, uint32_t ordinal,
                                        const char* dll) {
    auto& mem = emu_.Get<EmulatedMemory>();
    const uint32_t exp_pa  = MapRvaToPa(ed, ed.exp_rva);
    const uint32_t base    = mem.ReadWord(exp_pa + kExpOffBase);
    const uint32_t nfuncs  = mem.ReadWord(exp_pa + kExpOffNumFuncs);
    const uint32_t af_rva  = mem.ReadWord(exp_pa + kExpOffAddrFuncs);
    if (ordinal < base || (ordinal - base) >= nfuncs) {
        LOG(Caution, "CeImportBinder: %s ordinal %u outside export range [%u,%u)\n",
            dll, ordinal, base, base + nfuncs);
        CerfFatalExit();
    }
    const uint32_t func_rva = mem.ReadWord(MapRvaToPa(ed, af_rva + (ordinal - base) * 4u));
    if (func_rva == 0) {
        LOG(Caution, "CeImportBinder: %s ordinal %u not present\n", dll, ordinal);
        CerfFatalExit();
    }
    if (func_rva >= ed.exp_rva && func_rva < ed.exp_rva + ed.exp_size) {
        LOG(Caution, "CeImportBinder: %s ordinal %u is a forwarder (unsupported)\n",
            dll, ordinal);
        CerfFatalExit();
    }
    return ed.vbase + func_rva;
}

uint32_t CeImportBinder::ResolveName(const GuestExportDir& ed, const char* fn,
                                     const char* dll) {
    auto& mem = emu_.Get<EmulatedMemory>();
    const uint32_t exp_pa    = MapRvaToPa(ed, ed.exp_rva);
    const uint32_t nnames    = mem.ReadWord(exp_pa + kExpOffNumNames);
    const uint32_t names_rva = mem.ReadWord(exp_pa + kExpOffAddrNames);
    const uint32_t ords_rva  = mem.ReadWord(exp_pa + kExpOffAddrOrds);
    const uint32_t af_rva    = mem.ReadWord(exp_pa + kExpOffAddrFuncs);
    for (uint32_t i = 0; i < nnames; ++i) {
        const uint32_t name_rva = mem.ReadWord(MapRvaToPa(ed, names_rva + i * 4u));
        if (!GuestAsciiEquals(ed, name_rva, fn)) continue;
        const uint16_t fidx = mem.ReadHalf(MapRvaToPa(ed, ords_rva + i * 2u));
        const uint32_t func_rva = mem.ReadWord(MapRvaToPa(ed, af_rva + uint32_t(fidx) * 4u));
        if (func_rva >= ed.exp_rva && func_rva < ed.exp_rva + ed.exp_size) {
            LOG(Caution, "CeImportBinder: %s!%s is a forwarder (unsupported)\n", dll, fn);
            CerfFatalExit();
        }
        return ed.vbase + func_rva;
    }
    LOG(Caution, "CeImportBinder: %s does not export '%s'\n", dll, fn);
    CerfFatalExit();
}

bool CeImportBinder::GuestAsciiEquals(const GuestExportDir& ed, uint32_t name_rva,
                                      const char* s) {
    auto& mem = emu_.Get<EmulatedMemory>();
    for (uint32_t i = 0; ; ++i) {
        const uint8_t g = mem.ReadByte(MapRvaToPa(ed, name_rva + i));
        if (g != uint8_t(s[i])) return false;
        if (g == 0) return true;
    }
}
