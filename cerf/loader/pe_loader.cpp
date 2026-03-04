#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "pe_loader.h"
#include "../log.h"
#include <cstdio>
#include <cstring>
#include <algorithm>

bool PELoader::ParseHeaders(const uint8_t* data, size_t size, PEInfo& info) {
    if (size < sizeof(IMAGE_DOS_HEADER)) return false;

    auto* dos = (IMAGE_DOS_HEADER*)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        LOG_ERR("[PE] Invalid DOS signature\n");
        return false;
    }

    uint32_t pe_off = dos->e_lfanew;
    if (pe_off + sizeof(IMAGE_NT_HEADERS32) > size) return false;

    auto* nt = (IMAGE_NT_HEADERS32*)(data + pe_off);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        LOG_ERR("[PE] Invalid PE signature\n");
        return false;
    }

    auto& fh = nt->FileHeader;
    auto& oh = nt->OptionalHeader;

    info.machine = fh.Machine;
    info.num_sections = fh.NumberOfSections;
    info.is_dll = (fh.Characteristics & IMAGE_FILE_DLL) != 0;

    if (info.machine != 0x01C0 && info.machine != 0x01C2) {
        LOG_ERR("[PE] Not an ARM binary (machine=0x%04X)\n", info.machine);
        return false;
    }

    if (oh.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        LOG_ERR("[PE] Not PE32 format\n");
        return false;
    }

    info.image_base = oh.ImageBase;
    info.entry_point_rva = oh.AddressOfEntryPoint;
    info.size_of_image = oh.SizeOfImage;
    info.size_of_headers = oh.SizeOfHeaders;
    info.subsystem = oh.Subsystem;

    /* Parse data directories */
    if (oh.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
        info.reloc_rva = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        info.reloc_size = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    }
    if (oh.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
        info.rsrc_rva = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
        info.rsrc_size = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
    }
    if (oh.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
        info.export_rva = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        info.export_size = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }

    /* Parse section headers */
    auto* sections = (IMAGE_SECTION_HEADER*)((uint8_t*)&nt->OptionalHeader + fh.SizeOfOptionalHeader);
    for (int i = 0; i < info.num_sections; i++) {
        info.sections.push_back(sections[i]);
    }

    LOG(PE, "[PE] Machine=0x%04X ImageBase=0x%08X Entry=0x%08X SizeOfImage=0x%X Subsys=%d\n",
           info.machine, info.image_base, info.entry_point_rva, info.size_of_image, info.subsystem);
    LOG(PE, "[PE] Sections: %d, DLL=%d\n", info.num_sections, info.is_dll);

    for (auto& s : info.sections) {
        char name[9] = {};
        memcpy(name, s.Name, 8);
        LOG(PE, "[PE]  %-8s VirtRVA=0x%08X VirtSize=0x%08X RawOff=0x%08X RawSize=0x%08X\n",
               name, s.VirtualAddress, s.Misc.VirtualSize, s.PointerToRawData, s.SizeOfRawData);
    }

    return true;
}

bool PELoader::LoadSections(const uint8_t* data, size_t size, EmulatedMemory& mem, const PEInfo& info) {
    /* Allocate the entire image region */
    uint8_t* image = mem.Alloc(info.image_base, info.size_of_image);
    if (!image) return false;

    /* Copy headers */
    uint32_t hdr_copy = std::min((uint32_t)size, info.size_of_headers);
    memcpy(image, data, hdr_copy);

    /* Copy sections */
    for (auto& s : info.sections) {
        if (s.PointerToRawData == 0) continue;
        /* WinCE PE convention: SizeOfRawData may be 0 even when data exists.
           In that case, use VirtualSize as the on-disk data size. */
        DWORD raw_size = s.SizeOfRawData;
        if (raw_size == 0) raw_size = s.Misc.VirtualSize;
        if (raw_size == 0) continue;
        if (s.PointerToRawData + raw_size > size) {
            LOG_ERR("[PE] Section raw data exceeds file size\n");
            continue;
        }
        DWORD vsize = s.Misc.VirtualSize ? s.Misc.VirtualSize : raw_size;
        uint32_t copy_size = (raw_size < vsize) ? raw_size : vsize;
        memcpy(image + s.VirtualAddress, data + s.PointerToRawData, copy_size);
    }

    return true;
}

bool PELoader::ProcessRelocations(EmulatedMemory& mem, const PEInfo& info, uint32_t actual_base) {
    if (info.reloc_rva == 0 || info.reloc_size == 0) return true;

    int32_t delta = (int32_t)actual_base - (int32_t)info.image_base;
    if (delta == 0) return true; /* No relocation needed */

    uint32_t offset = 0;
    while (offset < info.reloc_size) {
        uint32_t block_rva = mem.Read32(actual_base + info.reloc_rva + offset);
        uint32_t block_size = mem.Read32(actual_base + info.reloc_rva + offset + 4);

        if (block_size == 0) break;

        uint32_t num_entries = (block_size - 8) / 2;
        for (uint32_t i = 0; i < num_entries; i++) {
            uint16_t entry = mem.Read16(actual_base + info.reloc_rva + offset + 8 + i * 2);
            uint16_t type = entry >> 12;
            uint16_t off = entry & 0xFFF;

            if (type == IMAGE_REL_BASED_HIGHLOW || type == 3) {
                uint32_t addr = actual_base + block_rva + off;
                uint32_t val = mem.Read32(addr);
                mem.Write32(addr, val + delta);
            } else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                /* Padding, skip */
            }
        }
        offset += block_size;
    }

    LOG(PE, "[PE] Relocations applied, delta=0x%X\n", delta);
    return true;
}

bool PELoader::ResolveImports(const uint8_t* data, size_t size, EmulatedMemory& mem, PEInfo& info) {
    auto* dos = (IMAGE_DOS_HEADER*)data;
    auto* nt = (IMAGE_NT_HEADERS32*)(data + dos->e_lfanew);
    auto& oh = nt->OptionalHeader;

    if (oh.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT) return true;

    uint32_t import_rva = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    uint32_t import_size = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

    if (import_rva == 0 || import_size == 0) return true;

    uint32_t base = info.image_base;
    uint32_t desc_addr = base + import_rva;

    while (true) {
        uint32_t ilt_rva = mem.Read32(desc_addr + 0);
        uint32_t name_rva = mem.Read32(desc_addr + 12);
        uint32_t iat_rva = mem.Read32(desc_addr + 16);

        if (ilt_rva == 0 && name_rva == 0) break;

        /* Read DLL name */
        char dll_name[256] = {};
        uint8_t* name_ptr = mem.Translate(base + name_rva);
        if (name_ptr) {
            strncpy(dll_name, (char*)name_ptr, 255);
        }

        LOG(PE, "[PE] Import DLL: %s\n", dll_name);

        /* Parse import entries from ILT (or IAT if ILT is 0) */
        uint32_t lookup_rva = (ilt_rva != 0) ? ilt_rva : iat_rva;
        uint32_t lookup_addr = base + lookup_rva;
        uint32_t iat_addr = base + iat_rva;

        for (uint32_t i = 0; ; i++) {
            uint32_t entry = mem.Read32(lookup_addr + i * 4);
            if (entry == 0) break;

            ImportEntry imp;
            imp.dll_name = dll_name;
            imp.iat_addr = iat_addr + i * 4;

            if (entry & 0x80000000) {
                imp.by_ordinal = true;
                imp.ordinal = (uint16_t)(entry & 0xFFFF);
                LOG(PE, "[PE]  Import by ordinal: %d\n", imp.ordinal);
            } else {
                imp.by_ordinal = false;
                uint8_t* hint_ptr = mem.Translate(base + entry);
                if (hint_ptr) {
                    imp.ordinal = *(uint16_t*)hint_ptr;
                    imp.func_name = (char*)(hint_ptr + 2);
                }
            }

            info.imports.push_back(imp);
        }

        desc_addr += 20; /* Next IMAGE_IMPORT_DESCRIPTOR */
    }

    LOG(PE, "[PE] Total imports: %zu\n", info.imports.size());
    return true;
}

/* Check if an address range overlaps any existing memory region */
static bool IsRegionFree(EmulatedMemory& mem, uint32_t base, uint32_t size) {
    for (auto& r : mem.regions) {
        if (base < r.base + r.size && base + size > r.base) {
            return false;
        }
    }
    return true;
}

/* Find a free base address for a DLL image */
static uint32_t FindFreeBase(EmulatedMemory& mem, uint32_t preferred, uint32_t size) {
    if (IsRegionFree(mem, preferred, size)) return preferred;

    /* Try addresses above preferred, in 0x10000 increments */
    uint32_t aligned_size = (size + 0xFFFF) & ~0xFFFF;
    for (uint32_t base = preferred + aligned_size; base < 0x70000000; base += 0x10000) {
        base = (base + 0xFFFF) & ~0xFFFF; /* 64KB align */
        if (IsRegionFree(mem, base, size)) {
            return base;
        }
    }
    return 0;
}

uint32_t PELoader::Load(const char* path, EmulatedMemory& mem, PEInfo& info) {
    /* Read the file */
    FILE* f = fopen(path, "rb");
    if (!f) {
        LOG_ERR("[PE] Cannot open: %s\n", path);
        return 0;
    }

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    std::vector<uint8_t> data(size);
    fread(data.data(), 1, size, f);
    fclose(f);

    LOG(PE, "[PE] Loading %s (%zu bytes)\n", path, size);

    if (!ParseHeaders(data.data(), size, info)) return 0;
    if (!LoadSections(data.data(), size, mem, info)) return 0;
    if (!ProcessRelocations(mem, info, info.image_base)) return 0;
    if (!ResolveImports(data.data(), size, mem, info)) return 0;

    uint32_t entry = info.image_base + info.entry_point_rva;
    LOG(PE, "[PE] Entry point: 0x%08X\n", entry);
    return entry;
}

uint32_t PELoader::LoadDll(const char* path, EmulatedMemory& mem, PEInfo& info) {
    /* Read the file */
    FILE* f = fopen(path, "rb");
    if (!f) {
        LOG_ERR("[PE] Cannot open: %s\n", path);
        return 0;
    }

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    std::vector<uint8_t> data(size);
    fread(data.data(), 1, size, f);
    fclose(f);

    LOG(PE, "[PE] Loading DLL %s (%zu bytes)\n", path, size);

    if (!ParseHeaders(data.data(), size, info)) return 0;

    /* Check if preferred base is available; relocate if needed */
    uint32_t original_base = info.image_base;
    uint32_t actual_base = FindFreeBase(mem, info.image_base, info.size_of_image);
    if (actual_base == 0) {
        LOG_ERR("[PE] Cannot find free base for DLL %s\n", path);
        return 0;
    }
    if (actual_base != original_base) {
        LOG(PE, "[PE] Relocating DLL from 0x%08X to 0x%08X\n", original_base, actual_base);
        info.image_base = actual_base;
    }

    if (!LoadSections(data.data(), size, mem, info)) return 0;

    /* Apply relocations using the original PE base to compute delta */
    if (actual_base != original_base) {
        if (info.reloc_rva == 0 || info.reloc_size == 0) {
            LOG_ERR("[PE] DLL needs relocation but has no .reloc section!\n");
            return 0;
        }
        int32_t delta = (int32_t)actual_base - (int32_t)original_base;
        uint32_t offset = 0;
        while (offset < info.reloc_size) {
            uint32_t block_rva = mem.Read32(actual_base + info.reloc_rva + offset);
            uint32_t block_size = mem.Read32(actual_base + info.reloc_rva + offset + 4);
            if (block_size == 0) break;

            uint32_t num_entries = (block_size - 8) / 2;
            for (uint32_t i = 0; i < num_entries; i++) {
                uint16_t entry = mem.Read16(actual_base + info.reloc_rva + offset + 8 + i * 2);
                uint16_t type = entry >> 12;
                uint16_t off = entry & 0xFFF;

                if (type == IMAGE_REL_BASED_HIGHLOW || type == 3) {
                    uint32_t addr = actual_base + block_rva + off;
                    uint32_t val = mem.Read32(addr);
                    mem.Write32(addr, val + delta);
                }
            }
            offset += block_size;
        }
        LOG(PE, "[PE] DLL relocated with delta=0x%X (%d reloc fixups)\n", delta, offset > 0 ? 1 : 0);
    }

    if (!ResolveImports(data.data(), size, mem, info)) return 0;

    uint32_t entry = info.image_base + info.entry_point_rva;
    LOG(PE, "[PE] DLL entry point: 0x%08X\n", entry);
    return entry;
}

uint32_t PELoader::ResolveExportOrdinal(EmulatedMemory& mem, const PEInfo& info, uint16_t ordinal) {
    if (info.export_rva == 0 || info.export_size == 0) return 0;

    uint32_t base = info.image_base;
    uint32_t export_dir = base + info.export_rva;

    /* IMAGE_EXPORT_DIRECTORY layout:
       +0x00: Characteristics
       +0x04: TimeDateStamp
       +0x08: MajorVersion/MinorVersion
       +0x0C: Name RVA
       +0x10: OrdinalBase
       +0x14: NumberOfFunctions
       +0x18: NumberOfNames
       +0x1C: AddressOfFunctions RVA
       +0x20: AddressOfNames RVA
       +0x24: AddressOfNameOrdinals RVA */

    uint32_t ordinal_base = mem.Read32(export_dir + 0x10);
    uint32_t num_functions = mem.Read32(export_dir + 0x14);
    uint32_t addr_of_functions = base + mem.Read32(export_dir + 0x1C);

    /* Convert ordinal to index */
    uint32_t index = ordinal - ordinal_base;
    if (index >= num_functions) {
        LOG(PE, "[PE] Export ordinal %d out of range (base=%d, count=%d)\n",
               ordinal, ordinal_base, num_functions);
        return 0;
    }

    uint32_t func_rva = mem.Read32(addr_of_functions + index * 4);
    if (func_rva == 0) return 0;

    /* Check for forwarded export (RVA points within export directory) */
    if (func_rva >= info.export_rva && func_rva < info.export_rva + info.export_size) {
        uint8_t* fwd = mem.Translate(base + func_rva);
        if (fwd) {
            LOG(PE, "[PE] Export ordinal %d is forwarded to: %s\n", ordinal, (char*)fwd);
        }
        return 0; /* Can't resolve forwarded exports */
    }

    uint32_t addr = base + func_rva;
    LOG(PE, "[PE] Resolved export ordinal %d -> 0x%08X (RVA=0x%08X)\n", ordinal, addr, func_rva);
    return addr;
}

uint32_t PELoader::ResolveExportName(EmulatedMemory& mem, const PEInfo& info, const std::string& name) {
    if (info.export_rva == 0 || info.export_size == 0) return 0;

    uint32_t base = info.image_base;
    uint32_t export_dir = base + info.export_rva;

    uint32_t ordinal_base = mem.Read32(export_dir + 0x10);
    uint32_t num_functions = mem.Read32(export_dir + 0x14);
    uint32_t num_names = mem.Read32(export_dir + 0x18);
    uint32_t addr_of_functions = base + mem.Read32(export_dir + 0x1C);
    uint32_t addr_of_names = base + mem.Read32(export_dir + 0x20);
    uint32_t addr_of_ordinals = base + mem.Read32(export_dir + 0x24);

    for (uint32_t i = 0; i < num_names; i++) {
        uint32_t name_rva = mem.Read32(addr_of_names + i * 4);
        uint8_t* name_ptr = mem.Translate(base + name_rva);
        if (name_ptr && strcmp((char*)name_ptr, name.c_str()) == 0) {
            uint16_t ordinal_index = mem.Read16(addr_of_ordinals + i * 2);
            if (ordinal_index >= num_functions) return 0;
            uint32_t func_rva = mem.Read32(addr_of_functions + ordinal_index * 4);
            if (func_rva == 0) return 0;
            uint32_t addr = base + func_rva;
            LOG(PE, "[PE] Resolved export '%s' -> 0x%08X\n", name.c_str(), addr);
            return addr;
        }
    }
    return 0;
}
