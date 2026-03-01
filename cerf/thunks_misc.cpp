/* Misc thunks: resources, debug, clipboard, shell, stubs */
#define NOMINMAX
#include "win32_thunks.h"
#include <cstdio>
#include <commctrl.h>
#include <algorithm>
#include <vector>

void Win32Thunks::RegisterMiscHandlers() {
    /* Resources */
    Thunk("LoadStringW", 874, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hmod = regs[0], str_id = regs[1], dst = regs[2], maxlen = regs[3];
        if (maxlen > 4096) maxlen = 4096;
        uint32_t bundle_id = (str_id / 16) + 1, string_idx = str_id % 16;
        uint32_t rsrc_rva = 0, rsrc_sz = 0; bool is_arm = false;
        if (hmod == emu_hinstance || hmod == 0) {
            is_arm = true; uint32_t base = emu_hinstance;
            uint32_t dos_lfanew = mem.Read32(base + 0x3C), nt_addr = base + dos_lfanew;
            uint32_t num_rva_sizes = mem.Read32(nt_addr + 0x74);
            if (num_rva_sizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
                rsrc_rva = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8);
                rsrc_sz = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8 + 4);
            }
            hmod = base;
        }
        for (auto& pair : loaded_dlls) {
            if (pair.second.base_addr == hmod) {
                is_arm = true; rsrc_rva = pair.second.pe_info.rsrc_rva;
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
                    ReleaseDC(NULL, hdc); regs[0] = (uint32_t)(uintptr_t)hbm;
                } else regs[0] = 0;
            } else {
                HMODULE native_mod = GetNativeModuleForResources(hmod);
                regs[0] = native_mod ? (uint32_t)(uintptr_t)LoadBitmapW(native_mod, MAKEINTRESOURCEW(name_id)) : 0;
            }
        } else {
            regs[0] = (uint32_t)(uintptr_t)LoadBitmapW((HINSTANCE)(intptr_t)(int32_t)hmod, MAKEINTRESOURCEW(name_id));
        }
        return true;
    });
    Thunk("LoadImageW", 730, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hmod = regs[0], name_id = regs[1], type = regs[2];
        int cx = (int)regs[3], cy = (int)ReadStackArg(regs, mem, 0);
        uint32_t fuLoad = ReadStackArg(regs, mem, 1);
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
    /* Debug */
    Thunk("OutputDebugStringW", 541, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[DEBUG] %ls\n", ReadWStringFromEmu(mem, regs[0]).c_str()); return true;
    });
    Thunk("NKDbgPrintfW", 545, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        printf("[NKDbg] %ls\n", ReadWStringFromEmu(mem, regs[0]).c_str()); return true;
    });
    /* Clipboard stubs */
    Thunk("OpenClipboard", 668, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 1; return true; });
    Thunk("CloseClipboard", 669, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 1; return true; });
    Thunk("EmptyClipboard", 677, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 1; return true; });
    Thunk("GetClipboardData", 672, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("SetClipboardData", 671, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("IsClipboardFormatAvailable", 678, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("EnumClipboardFormats", 675, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    /* Caret stubs */
    Thunk("CreateCaret", 658, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 1; return true; });
    Thunk("HideCaret", 660, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 1; return true; });
    Thunk("ShowCaret", 661, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 1; return true; });
    /* Sound stubs */
    Thunk("sndPlaySoundW", 377, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 1; return true; });
    Thunk("waveOutSetVolume", 382, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    /* RAS stubs */
    auto ras_stub = [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; };
    Thunk("RasDial", 342, ras_stub);
    Thunk("RasHangup", ras_stub);
    thunk_handlers["RasHangUp"] = ras_stub;
    /* C runtime stubs */
    Thunk("_purecall", 1092, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("terminate", 1556, [](uint32_t* regs, EmulatedMemory&) -> bool { ExitProcess(3); return true; });
    Thunk("__security_gen_cookie", 1875, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0xBB40E64E; return true; });
    Thunk("__security_gen_cookie2", 2696, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0xBB40E64E; return true; });
    Thunk("CeGenRandom", 1601, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        for (uint32_t i = 0; i < regs[0]; i++) mem.Write8(regs[1] + i, (uint8_t)(rand() & 0xFF));
        regs[0] = 1; return true;
    });
    Thunk("MulDiv", 1877, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = MulDiv((int)regs[0], (int)regs[1], (int)regs[2]); return true;
    });
    Thunk("_except_handler4_common", 87, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("setjmp", 2054, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("_setjmp3", [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    /* Misc stubs */
    auto stub0 = [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; };
    auto stub1 = [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 1; return true; };
    Thunk("FlushInstructionCache", 508, stub1);
    Thunk("GetProcessIndexFromID", stub1);
    Thunk("EventModify", 494, stub1);
    Thunk("GlobalAddAtomW", 1519, stub1);
    Thunk("GetAPIAddress", 32, stub0);
    Thunk("WaitForAPIReady", 2562, stub0);
    Thunk("__GetUserKData", 2528, stub0);
    /* Gesture stubs */
    Thunk("RegisterDefaultGestureHandler", 2928, stub0);
    Thunk("GetGestureInfo", 2925, stub0);
    Thunk("GetGestureExtraArguments", stub0);
    Thunk("CloseGestureInfoHandle", 2924, stub0);
    /* Shell stubs */
    Thunk("SHGetSpecialFolderPath", 295, stub0);
    Thunk("ShellExecuteEx", 480, stub0);
    Thunk("SHLoadDIBitmap", 487, stub0);
    /* Common controls */
    Thunk("ImageList_Create", 742, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)(uintptr_t)ImageList_Create(regs[0], regs[1], regs[2], regs[3], ReadStackArg(regs, mem, 0));
        return true;
    });
    Thunk("ImageList_Destroy", 743, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_Destroy((HIMAGELIST)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("ImageList_Add", 738, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_Add((HIMAGELIST)(intptr_t)(int32_t)regs[0],
            (HBITMAP)(intptr_t)(int32_t)regs[1], (HBITMAP)(intptr_t)(int32_t)regs[2]);
        return true;
    });
    Thunk("ImageList_Draw", 748, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = ImageList_Draw((HIMAGELIST)(intptr_t)(int32_t)regs[0], regs[1],
            (HDC)(intptr_t)(int32_t)regs[2], regs[3], ReadStackArg(regs, mem, 0), ReadStackArg(regs, mem, 1));
        return true;
    });
    Thunk("ImageList_DrawEx", 749, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = ImageList_DrawEx((HIMAGELIST)(intptr_t)(int32_t)regs[0], regs[1],
            (HDC)(intptr_t)(int32_t)regs[2], regs[3],
            ReadStackArg(regs, mem, 0), ReadStackArg(regs, mem, 1), ReadStackArg(regs, mem, 2),
            ReadStackArg(regs, mem, 3), ReadStackArg(regs, mem, 4), ReadStackArg(regs, mem, 5));
        return true;
    });
    Thunk("ImageList_GetImageCount", 756, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_GetImageCount((HIMAGELIST)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("ImageList_GetIconSize", 755, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int cx, cy; BOOL ret = ImageList_GetIconSize((HIMAGELIST)(intptr_t)(int32_t)regs[0], &cx, &cy);
        if (regs[1]) mem.Write32(regs[1], cx); if (regs[2]) mem.Write32(regs[2], cy);
        regs[0] = ret; return true;
    });
    /* IMM stubs */
    Thunk("ImmAssociateContext", 770, stub0);
    Thunk("ImmGetContext", 783, stub0);
    Thunk("ImmReleaseContext", 803, stub0);
    /* Process/thread stubs */
    Thunk("CreateThread", 492, stub0);
    Thunk("CreateProcessW", 493, stub0);
    Thunk("TerminateThread", 491, stub0);
    Thunk("SetThreadPriority", 514, stub0);
    Thunk("GetExitCodeProcess", 519, stub0);
    Thunk("OpenProcess", 509, stub0);
    Thunk("WaitForMultipleObjects", 498, stub0);
    Thunk("CreateFileMappingW", 548, stub0);
    Thunk("MapViewOfFile", 549, stub0);
    Thunk("UnmapViewOfFile", 550, stub0);
    /* Ordinal-only entries (no handler, for logging) */
    ThunkOrdinal("Shell_NotifyIcon", 481);
    ThunkOrdinal("SHCreateShortcut", 484);
    ThunkOrdinal("GetOwnerProcess", 606);
    ThunkOrdinal("Random", 80);
}
