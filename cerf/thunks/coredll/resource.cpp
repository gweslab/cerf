#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Resource loading thunks: LoadStringW, LoadBitmapW, LoadImageW, FindResource, LoadAcceleratorsW */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <shellapi.h>

void Win32Thunks::RegisterResourceHandlers() {
    Thunk("LoadStringW", 874, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hmod = regs[0], str_id = regs[1], dst = regs[2], maxlen = regs[3];
        if (maxlen > 4096) maxlen = 4096;
        uint32_t bundle_id = (str_id / 16) + 1, string_idx = str_id % 16;
        uint32_t rsrc_rva = 0, rsrc_sz = 0; bool is_arm = false;
        uint32_t arm_base = 0;
        if (hmod == emu_hinstance || hmod == 0) {
            is_arm = true; arm_base = emu_hinstance;
            uint32_t dos_lfanew = mem.Read32(arm_base + 0x3C), nt_addr = arm_base + dos_lfanew;
            uint32_t num_rva_sizes = mem.Read32(nt_addr + 0x74);
            if (num_rva_sizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
                rsrc_rva = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8);
                rsrc_sz = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8 + 4);
            }
            hmod = arm_base;
        }
        for (auto& pair : loaded_dlls) {
            if (pair.second.base_addr == hmod) {
                is_arm = true; arm_base = pair.second.base_addr;
                rsrc_rva = pair.second.pe_info.rsrc_rva;
                rsrc_sz = pair.second.pe_info.rsrc_size; break;
            }
        }
        if (is_arm && rsrc_rva) {
            uint32_t data_rva = 0, data_size = 0;
            if (FindResourceInPE(hmod, rsrc_rva, rsrc_sz, 6, bundle_id, data_rva, data_size)) {
                uint8_t* data = mem.Translate(hmod + data_rva);
                if (data) {
                    uint16_t* p = (uint16_t*)data;
                    for (uint32_t i = 0; i < string_idx && (uint8_t*)p < data + data_size; i++) {
                        uint16_t len = *p++; p += len;
                    }
                    if ((uint8_t*)p < data + data_size) {
                        uint16_t len = *p++;
                        if (maxlen == 0 && dst == 0) {
                            /* Special case: nBufferMax=0, lpBuffer=NULL.
                               Return a direct pointer to the string in the resource section.
                               WinCE/Win32 LoadStringW returns a read-only pointer (not null-terminated)
                               and the character count. CStringRes relies on this. */
                            uint32_t str_arm_addr = hmod + data_rva + (uint32_t)((uint8_t*)p - data);
                            regs[0] = str_arm_addr;
                            return true;
                        }
                        uint32_t copy_len = (len < maxlen - 1) ? len : maxlen - 1;
                        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, p[i]);
                        mem.Write16(dst + copy_len * 2, 0);
                        regs[0] = copy_len; return true;
                    }
                }
            }
            if (dst && maxlen > 0) mem.Write16(dst, 0);
            regs[0] = 0;
        } else {
            wchar_t buf[1024] = {}; if (maxlen > 1024) maxlen = 1024;
            int ret = LoadStringW(GetModuleHandleW(NULL), str_id, buf, (int)maxlen);
            for (int i = 0; i <= ret && i < (int)maxlen; i++) mem.Write16(dst + i * 2, buf[i]);
            regs[0] = ret;
        }
        return true;
    });
    Thunk("LoadBitmapW", 873, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hmod = regs[0], name_id = regs[1];
        bool is_arm_module = (hmod == emu_hinstance);
        for (auto& pair : loaded_dlls) { if (pair.second.base_addr == hmod) { is_arm_module = true; break; } }
        if (is_arm_module) {
            uint32_t rsrc_rva = 0, rsrc_sz = 0;
            if (hmod == emu_hinstance) {
                uint32_t dos_lfanew = mem.Read32(hmod + 0x3C), nt_addr = hmod + dos_lfanew;
                uint32_t n = mem.Read32(nt_addr + 0x74);
                if (n > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
                    rsrc_rva = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8);
                    rsrc_sz = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8 + 4);
                }
            }
            for (auto& pair : loaded_dlls) {
                if (pair.second.base_addr == hmod) {
                    rsrc_rva = pair.second.pe_info.rsrc_rva; rsrc_sz = pair.second.pe_info.rsrc_size; break;
                }
            }
            uint32_t data_rva = 0, data_size = 0;
            if (rsrc_rva && FindResourceInPE(hmod, rsrc_rva, rsrc_sz, (uint32_t)RT_BITMAP, name_id, data_rva, data_size)) {
                uint8_t* bmp_data = mem.Translate(hmod + data_rva);
                if (bmp_data && data_size > sizeof(BITMAPINFOHEADER)) {
                    BITMAPINFO* bmi = (BITMAPINFO*)bmp_data;
                    HDC hdc = GetDC(NULL);
                    int colors = (bmi->bmiHeader.biBitCount <= 8)
                        ? (bmi->bmiHeader.biClrUsed ? bmi->bmiHeader.biClrUsed : (1 << bmi->bmiHeader.biBitCount)) : 0;
                    uint8_t* bits = bmp_data + sizeof(BITMAPINFOHEADER) + colors * sizeof(RGBQUAD);
                    HBITMAP hbm = CreateDIBitmap(hdc, &bmi->bmiHeader, CBM_INIT, bits, bmi, DIB_RGB_COLORS);
                    LOG(API, "[API] LoadBitmapW(0x%08X, %d) -> ARM rsrc: %dx%d %dbpp %dcolors hbm=%p (data_size=%d)\n",
                        hmod, name_id, bmi->bmiHeader.biWidth, bmi->bmiHeader.biHeight,
                        bmi->bmiHeader.biBitCount, colors, hbm, data_size);
                    ReleaseDC(NULL, hdc); regs[0] = (uint32_t)(uintptr_t)hbm;
                } else regs[0] = 0;
            } else {
                HMODULE native_mod = GetNativeModuleForResources(hmod);
                regs[0] = native_mod ? (uint32_t)(uintptr_t)LoadBitmapW(native_mod, MAKEINTRESOURCEW(name_id)) : 0;
                LOG(API, "[API] LoadBitmapW(0x%08X, %d) -> native fallback: %p\n",
                    hmod, name_id, (void*)(uintptr_t)regs[0]);
            }
        } else {
            regs[0] = (uint32_t)(uintptr_t)LoadBitmapW((HINSTANCE)(intptr_t)(int32_t)hmod, MAKEINTRESOURCEW(name_id));
            LOG(API, "[API] LoadBitmapW(0x%08X, %d) -> non-ARM: %p\n",
                hmod, name_id, (void*)(uintptr_t)regs[0]);
        }
        return true;
    });
    Thunk("LoadImageW", 730, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hmod = regs[0], name_id = regs[1], type = regs[2];
        int cx = (int)regs[3], cy = (int)ReadStackArg(regs, mem, 0);
        uint32_t fuLoad = ReadStackArg(regs, mem, 1);
        LOG(API, "[API] LoadImageW(hmod=0x%08X, id=%d, type=%d, cx=%d, cy=%d, flags=0x%X)\n",
            hmod, name_id, type, cx, cy, fuLoad);
        bool is_arm_module = (hmod == emu_hinstance);
        for (auto& pair : loaded_dlls) { if (pair.second.base_addr == hmod) { is_arm_module = true; break; } }
        if (is_arm_module && type == IMAGE_BITMAP) {
            uint32_t rsrc_rva = 0, rsrc_sz = 0;
            if (hmod == emu_hinstance) {
                uint32_t dos_lfanew = mem.Read32(hmod + 0x3C), nt_addr = hmod + dos_lfanew;
                uint32_t n = mem.Read32(nt_addr + 0x74);
                if (n > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
                    rsrc_rva = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8);
                    rsrc_sz = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8 + 4);
                }
            }
            for (auto& pair : loaded_dlls) {
                if (pair.second.base_addr == hmod) {
                    rsrc_rva = pair.second.pe_info.rsrc_rva; rsrc_sz = pair.second.pe_info.rsrc_size; break;
                }
            }
            uint32_t data_rva = 0, data_size = 0;
            if (rsrc_rva && FindResourceInPE(hmod, rsrc_rva, rsrc_sz, (uint32_t)RT_BITMAP, name_id, data_rva, data_size)) {
                uint8_t* bmp_data = mem.Translate(hmod + data_rva);
                if (bmp_data && data_size > sizeof(BITMAPINFOHEADER)) {
                    BITMAPINFO* bmi = (BITMAPINFO*)bmp_data;
                    HDC hdc = GetDC(NULL);
                    int colors = (bmi->bmiHeader.biBitCount <= 8)
                        ? (bmi->bmiHeader.biClrUsed ? bmi->bmiHeader.biClrUsed : (1 << bmi->bmiHeader.biBitCount)) : 0;
                    uint8_t* bits = bmp_data + sizeof(BITMAPINFOHEADER) + colors * sizeof(RGBQUAD);
                    HBITMAP hbm = CreateDIBitmap(hdc, &bmi->bmiHeader, CBM_INIT, bits, bmi, DIB_RGB_COLORS);
                    ReleaseDC(NULL, hdc); regs[0] = (uint32_t)(uintptr_t)hbm;
                } else regs[0] = 0;
            } else regs[0] = 0;
        } else if (!is_arm_module || hmod == 0) {
            regs[0] = (uint32_t)(uintptr_t)LoadImageW(
                (HINSTANCE)(intptr_t)(int32_t)hmod, MAKEINTRESOURCEW(name_id), type, cx, cy, fuLoad);
        } else {
            HMODULE native_mod = GetNativeModuleForResources(hmod);
            regs[0] = native_mod
                ? (uint32_t)(uintptr_t)LoadImageW(native_mod, MAKEINTRESOURCEW(name_id), type, cx, cy, fuLoad) : 0;
        }
        /* Fallback for ceshell.dll system icons (5376-5381).
           The bundled ceshell.dll lacks icon resources, so CIconCache::RebuildSystemImageList
           fails. HINST_CESHELL may be NULL (hmod=0) if DllMain didn't set it.
           Provide native Windows shell icons using ExtractIconExW from shell32.
           Icon mapping: 5376=file, 5377=exe, 5378=folder, 5379=open folder,
           5380=drive, 5381=shortcut */
        if (regs[0] == 0 && type == IMAGE_ICON && name_id >= 5376 && name_id <= 5381) {
            /* shell32.dll icon indices: 0=unknown file, 2=exe, 3=closed folder,
               4=open folder, 8=drive, 29=shortcut overlay (use 0 as shortcut fallback) */
            int shell32_idx = 0;
            switch (name_id) {
            case 5376: shell32_idx = 0; break;   /* generic file */
            case 5377: shell32_idx = 2; break;   /* executable */
            case 5378: shell32_idx = 3; break;   /* closed folder */
            case 5379: shell32_idx = 4; break;   /* open folder */
            case 5380: shell32_idx = 8; break;   /* drive */
            case 5381: shell32_idx = 0; break;   /* shortcut (use file icon) */
            }
            HICON hSmall = NULL, hLarge = NULL;
            ExtractIconExW(L"shell32.dll", shell32_idx,
                cx > 16 ? &hLarge : NULL,
                cx <= 16 ? &hSmall : NULL, 1);
            HICON hIcon = (cx <= 16) ? hSmall : hLarge;
            if (hIcon) {
                regs[0] = (uint32_t)(uintptr_t)hIcon;
                LOG(API, "[API] LoadImageW: ceshell icon %d (%dx%d) -> shell32 idx %d = 0x%08X\n",
                    name_id, cx, cy, shell32_idx, regs[0]);
                /* Destroy the other icon we didn't use */
                if (hSmall && hSmall != hIcon) DestroyIcon(hSmall);
                if (hLarge && hLarge != hIcon) DestroyIcon(hLarge);
            }
        }
        return true;
    });
    Thunk("FindResourceW", 532, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hmod = regs[0], name_arg = regs[1], type_arg = regs[2];
        uint32_t rsrc_rva = 0, rsrc_sz = 0;
        if (hmod == emu_hinstance) {
            uint32_t dos_lfanew = mem.Read32(hmod + 0x3C), nt_addr = hmod + dos_lfanew;
            uint32_t n = mem.Read32(nt_addr + 0x74);
            if (n > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
                rsrc_rva = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8);
                rsrc_sz = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8 + 4);
            }
        }
        for (auto& pair : loaded_dlls) {
            if (pair.second.base_addr == hmod) {
                rsrc_rva = pair.second.pe_info.rsrc_rva; rsrc_sz = pair.second.pe_info.rsrc_size; break;
            }
        }
        uint32_t data_rva = 0, data_size = 0;
        if (rsrc_rva && FindResourceInPE(hmod, rsrc_rva, rsrc_sz, type_arg, name_arg, data_rva, data_size)) {
            uint32_t fake = next_rsrc_handle++;
            rsrc_map[fake] = { data_rva, data_size, hmod };
            regs[0] = fake;
        } else regs[0] = 0;
        return true;
    });
    Thunk("LoadResource", 533, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        auto it = rsrc_map.find(regs[1]);
        regs[0] = (it != rsrc_map.end()) ? it->second.module_base + it->second.data_rva : 0;
        return true;
    });
    Thunk("SizeofResource", 534, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        auto it = rsrc_map.find(regs[1]);
        regs[0] = (it != rsrc_map.end()) ? it->second.data_size : 0;
        return true;
    });
    Thunk("LoadAcceleratorsW", 94, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hmod = regs[0], name_id = regs[1];
        LOG(API, "[API] LoadAcceleratorsW(0x%08X, %d)\n", hmod, name_id);
        uint32_t rsrc_rva = 0, rsrc_sz = 0;
        bool is_arm = (hmod == emu_hinstance);
        if (is_arm) {
            uint32_t dos_lfanew = mem.Read32(hmod + 0x3C), nt_addr = hmod + dos_lfanew;
            uint32_t n = mem.Read32(nt_addr + 0x74);
            if (n > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
                rsrc_rva = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8);
                rsrc_sz = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8 + 4);
            }
        }
        for (auto& pair : loaded_dlls) {
            if (pair.second.base_addr == hmod) {
                is_arm = true; rsrc_rva = pair.second.pe_info.rsrc_rva;
                rsrc_sz = pair.second.pe_info.rsrc_size; break;
            }
        }
        if (is_arm && rsrc_rva) {
            uint32_t data_rva = 0, data_size = 0;
            if (FindResourceInPE(hmod, rsrc_rva, rsrc_sz, 9, name_id, data_rva, data_size)) {
                uint8_t* data = mem.Translate(hmod + data_rva);
                if (data && data_size >= 8) {
                    int count = data_size / 8;
                    ACCEL* accels = new ACCEL[count];
                    for (int i = 0; i < count; i++) {
                        uint16_t* entry = (uint16_t*)(data + i * 8);
                        accels[i].fVirt = (BYTE)entry[0];
                        accels[i].key = entry[1];
                        accels[i].cmd = entry[2] | (entry[3] << 16);
                    }
                    HACCEL h = CreateAcceleratorTableW(accels, count);
                    delete[] accels;
                    regs[0] = (uint32_t)(uintptr_t)h;
                    LOG(API, "[API]   -> HACCEL 0x%08X (%d entries)\n", regs[0], count);
                    return true;
                }
            }
        }
        HMODULE native_mod = is_arm ? GetNativeModuleForResources(hmod) : (HMODULE)(intptr_t)(int32_t)hmod;
        regs[0] = native_mod ? (uint32_t)(uintptr_t)LoadAcceleratorsW(native_mod, MAKEINTRESOURCEW(name_id)) : 0;
        return true;
    });
}
