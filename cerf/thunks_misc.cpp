/* Misc thunks: resources, debug, clipboard, shell, stubs */
#define NOMINMAX
#include "win32_thunks.h"
#include <cstdio>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <objbase.h>
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
    Thunk("LoadAcceleratorsW", 94, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hmod = regs[0], name_id = regs[1];
        printf("[THUNK] LoadAcceleratorsW(0x%08X, %d)\n", hmod, name_id);
        /* Try ARM PE resources first */
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
            /* RT_ACCELERATOR = 9 */
            if (FindResourceInPE(hmod, rsrc_rva, rsrc_sz, 9, name_id, data_rva, data_size)) {
                uint8_t* data = mem.Translate(hmod + data_rva);
                if (data && data_size >= 8) {
                    /* Accelerator table entries are 8 bytes each, same format as native */
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
                    printf("[THUNK]   -> HACCEL 0x%08X (%d entries)\n", regs[0], count);
                    return true;
                }
            }
        }
        /* Fallback to native */
        HMODULE native_mod = is_arm ? GetNativeModuleForResources(hmod) : (HMODULE)(intptr_t)(int32_t)hmod;
        regs[0] = native_mod ? (uint32_t)(uintptr_t)LoadAcceleratorsW(native_mod, MAKEINTRESOURCEW(name_id)) : 0;
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
    Thunk("OpenClipboard", 668, [](uint32_t* regs, EmulatedMemory&) -> bool { printf("[THUNK] [STUB] OpenClipboard -> 1\n"); regs[0] = 1; return true; });
    Thunk("CloseClipboard", 669, [](uint32_t* regs, EmulatedMemory&) -> bool { printf("[THUNK] [STUB] CloseClipboard -> 1\n"); regs[0] = 1; return true; });
    Thunk("EmptyClipboard", 677, [](uint32_t* regs, EmulatedMemory&) -> bool { printf("[THUNK] [STUB] EmptyClipboard -> 1\n"); regs[0] = 1; return true; });
    Thunk("GetClipboardData", 672, [](uint32_t* regs, EmulatedMemory&) -> bool { printf("[THUNK] [STUB] GetClipboardData -> 0\n"); regs[0] = 0; return true; });
    Thunk("SetClipboardData", 671, [](uint32_t* regs, EmulatedMemory&) -> bool { printf("[THUNK] [STUB] SetClipboardData -> 0\n"); regs[0] = 0; return true; });
    Thunk("IsClipboardFormatAvailable", 678, [](uint32_t* regs, EmulatedMemory&) -> bool { printf("[THUNK] [STUB] IsClipboardFormatAvailable -> 0\n"); regs[0] = 0; return true; });
    Thunk("EnumClipboardFormats", 675, [](uint32_t* regs, EmulatedMemory&) -> bool { printf("[THUNK] [STUB] EnumClipboardFormats -> 0\n"); regs[0] = 0; return true; });
    /* Caret stubs */
    Thunk("CreateCaret", 658, [](uint32_t* regs, EmulatedMemory&) -> bool { printf("[THUNK] [STUB] CreateCaret -> 1\n"); regs[0] = 1; return true; });
    Thunk("HideCaret", 660, [](uint32_t* regs, EmulatedMemory&) -> bool { printf("[THUNK] [STUB] HideCaret -> 1\n"); regs[0] = 1; return true; });
    Thunk("ShowCaret", 661, [](uint32_t* regs, EmulatedMemory&) -> bool { printf("[THUNK] [STUB] ShowCaret -> 1\n"); regs[0] = 1; return true; });
    /* Sound stubs */
    Thunk("sndPlaySoundW", 377, [](uint32_t* regs, EmulatedMemory&) -> bool { printf("[THUNK] [STUB] sndPlaySoundW -> 1\n"); regs[0] = 1; return true; });
    Thunk("waveOutSetVolume", 382, [](uint32_t* regs, EmulatedMemory&) -> bool { printf("[THUNK] [STUB] waveOutSetVolume -> 0\n"); regs[0] = 0; return true; });
    /* RAS stubs */
    Thunk("RasDial", 342, [](uint32_t* regs, EmulatedMemory&) -> bool { printf("[THUNK] [STUB] RasDial -> 0\n"); regs[0] = 0; return true; });
    Thunk("RasHangup", [](uint32_t* regs, EmulatedMemory&) -> bool { printf("[THUNK] [STUB] RasHangup -> 0\n"); regs[0] = 0; return true; });
    thunk_handlers["RasHangUp"] = thunk_handlers["RasHangup"];
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
    /* Misc stubs - logging helpers */
    auto stub0 = [](const char* name) -> ThunkHandler {
        return [name](uint32_t* regs, EmulatedMemory&) -> bool {
            printf("[THUNK] [STUB] %s -> 0\n", name); regs[0] = 0; return true;
        };
    };
    auto stub1 = [](const char* name) -> ThunkHandler {
        return [name](uint32_t* regs, EmulatedMemory&) -> bool {
            printf("[THUNK] [STUB] %s -> 1\n", name); regs[0] = 1; return true;
        };
    };
    Thunk("FlushInstructionCache", 508, stub1("FlushInstructionCache"));
    Thunk("GetProcessIndexFromID", stub1("GetProcessIndexFromID"));
    Thunk("EventModify", 494, stub1("EventModify"));
    Thunk("GlobalAddAtomW", 1519, stub1("GlobalAddAtomW"));
    Thunk("GetAPIAddress", 32, stub0("GetAPIAddress"));
    Thunk("WaitForAPIReady", 2562, stub0("WaitForAPIReady"));
    Thunk("__GetUserKData", 2528, stub0("__GetUserKData"));
    /* Gesture stubs */
    Thunk("RegisterDefaultGestureHandler", 2928, stub0("RegisterDefaultGestureHandler"));
    Thunk("GetGestureInfo", 2925, stub0("GetGestureInfo"));
    Thunk("GetGestureExtraArguments", stub0("GetGestureExtraArguments"));
    Thunk("CloseGestureInfoHandle", 2924, stub0("CloseGestureInfoHandle"));
    /* Shell stubs */
    Thunk("SHGetSpecialFolderPath", 295, stub0("SHGetSpecialFolderPath"));
    Thunk("ShellExecuteEx", 480, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t sei_addr = regs[0];
        if (!sei_addr) { regs[0] = 0; SetLastError(ERROR_INVALID_PARAMETER); return true; }
        /* WinCE SHELLEXECUTEINFO layout (all 32-bit pointers):
           0x00 cbSize, 0x04 fMask, 0x08 hwnd, 0x0C lpVerb, 0x10 lpFile,
           0x14 lpParameters, 0x18 lpDirectory, 0x1C nShow, 0x20 hInstApp */
        uint32_t fMask     = mem.Read32(sei_addr + 0x04);
        uint32_t hwnd_val  = mem.Read32(sei_addr + 0x08);
        uint32_t verb_ptr  = mem.Read32(sei_addr + 0x0C);
        uint32_t file_ptr  = mem.Read32(sei_addr + 0x10);
        uint32_t params_ptr= mem.Read32(sei_addr + 0x14);
        uint32_t dir_ptr   = mem.Read32(sei_addr + 0x18);
        int nShow          = (int)mem.Read32(sei_addr + 0x1C);
        std::wstring verb, file, params, dir;
        if (verb_ptr) verb = ReadWStringFromEmu(mem, verb_ptr);
        if (file_ptr) file = ReadWStringFromEmu(mem, file_ptr);
        if (params_ptr) params = ReadWStringFromEmu(mem, params_ptr);
        if (dir_ptr) dir = ReadWStringFromEmu(mem, dir_ptr);
        printf("[THUNK] ShellExecuteEx(verb='%ls', file='%ls', params='%ls', dir='%ls', nShow=%d)\n",
               verb.c_str(), file.c_str(), params.c_str(), dir.c_str(), nShow);
        SHELLEXECUTEINFOW native_sei = {};
        native_sei.cbSize = sizeof(SHELLEXECUTEINFOW);
        native_sei.fMask = fMask;
        native_sei.hwnd = (HWND)(intptr_t)(int32_t)hwnd_val;
        native_sei.lpVerb = verb.empty() ? NULL : verb.c_str();
        native_sei.lpFile = file.empty() ? NULL : file.c_str();
        native_sei.lpParameters = params.empty() ? NULL : params.c_str();
        native_sei.lpDirectory = dir.empty() ? NULL : dir.c_str();
        native_sei.nShow = nShow;
        BOOL ret = ShellExecuteExW(&native_sei);
        /* Write back hInstApp and hProcess */
        mem.Write32(sei_addr + 0x20, (uint32_t)(uintptr_t)native_sei.hInstApp);
        if (fMask & SEE_MASK_NOCLOSEPROCESS)
            mem.Write32(sei_addr + 0x38, (uint32_t)(uintptr_t)native_sei.hProcess);
        printf("[THUNK]   -> %s\n", ret ? "OK" : "FAILED");
        regs[0] = ret;
        return true;
    });
    Thunk("SHLoadDIBitmap", 487, stub0("SHLoadDIBitmap"));
    /* Common dialogs - marshal WinCE 32-bit OPENFILENAMEW to native */
    auto getFileNameImpl = [this](uint32_t* regs, EmulatedMemory& mem, bool isSave) -> bool {
        uint32_t ofn_addr = regs[0];
        if (!ofn_addr) { regs[0] = 0; return true; }
        /* Read WinCE OPENFILENAMEW fields from emulated memory */
        uint32_t hwnd_val      = mem.Read32(ofn_addr + 0x04);
        uint32_t filter_ptr    = mem.Read32(ofn_addr + 0x0C);
        uint32_t filter_idx    = mem.Read32(ofn_addr + 0x18);
        uint32_t file_ptr      = mem.Read32(ofn_addr + 0x1C);
        uint32_t max_file      = mem.Read32(ofn_addr + 0x20);
        uint32_t init_dir_ptr  = mem.Read32(ofn_addr + 0x2C);
        uint32_t title_ptr     = mem.Read32(ofn_addr + 0x30);
        uint32_t flags         = mem.Read32(ofn_addr + 0x34);
        uint32_t def_ext_ptr   = mem.Read32(ofn_addr + 0x3C);
        /* Read strings from emulated memory */
        std::wstring filter, file_buf, init_dir, title, def_ext;
        if (filter_ptr) {
            /* Filter is double-null-terminated list of pairs */
            for (uint32_t i = 0; i < 4096; i++) {
                wchar_t c = (wchar_t)mem.Read16(filter_ptr + i * 2);
                filter += c;
                if (c == 0 && i > 0 && filter[filter.size() - 2] == 0) break;
            }
        }
        if (file_ptr && max_file > 0) {
            for (uint32_t i = 0; i < max_file; i++) {
                wchar_t c = (wchar_t)mem.Read16(file_ptr + i * 2);
                file_buf += c;
                if (c == 0) break;
            }
        }
        if (init_dir_ptr) init_dir = ReadWStringFromEmu(mem, init_dir_ptr);
        if (title_ptr) title = ReadWStringFromEmu(mem, title_ptr);
        if (def_ext_ptr) def_ext = ReadWStringFromEmu(mem, def_ext_ptr);
        printf("[THUNK] %s(filter='%ls', file='%ls', dir='%ls', flags=0x%X)\n",
               isSave ? "GetSaveFileNameW" : "GetOpenFileNameW",
               filter.empty() ? L"" : filter.c_str(), file_buf.c_str(),
               init_dir.empty() ? L"" : init_dir.c_str(), flags);
        /* Build native OPENFILENAMEW */
        /* Ensure file buffer is large enough */
        if (max_file < 260) max_file = 260;
        std::vector<wchar_t> native_file(max_file, 0);
        if (!file_buf.empty()) wcscpy_s(native_file.data(), max_file, file_buf.c_str());
        OPENFILENAMEW ofn = {};
        ofn.lStructSize = sizeof(OPENFILENAMEW);
        ofn.hwndOwner = (HWND)(intptr_t)(int32_t)hwnd_val;
        ofn.lpstrFilter = filter.empty() ? L"All Files\0*.*\0" : filter.c_str();
        ofn.nFilterIndex = filter_idx;
        ofn.lpstrFile = native_file.data();
        ofn.nMaxFile = max_file;
        ofn.lpstrInitialDir = init_dir.empty() ? NULL : init_dir.c_str();
        ofn.lpstrTitle = title.empty() ? NULL : title.c_str();
        ofn.lpstrDefExt = def_ext.empty() ? NULL : def_ext.c_str();
        /* Map WinCE flags to native, strip unsupported ones */
        ofn.Flags = flags & (OFN_READONLY | OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY |
                    OFN_NOCHANGEDIR | OFN_NOVALIDATE | OFN_ALLOWMULTISELECT |
                    OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_CREATEPROMPT |
                    OFN_NOREADONLYRETURN | OFN_EXPLORER);
        ofn.Flags |= OFN_EXPLORER; /* Always use explorer style */
        BOOL result = isSave ? GetSaveFileNameW(&ofn) : GetOpenFileNameW(&ofn);
        if (result) {
            /* Write result back to emulated memory */
            uint32_t orig_max = mem.Read32(ofn_addr + 0x20);
            for (uint32_t i = 0; i < orig_max && i < max_file; i++) {
                mem.Write16(file_ptr + i * 2, native_file[i]);
                if (native_file[i] == 0) break;
            }
            /* Update nFileOffset and nFileExtension */
            mem.Write16(ofn_addr + 0x38, ofn.nFileOffset);
            mem.Write16(ofn_addr + 0x3A, ofn.nFileExtension);
            /* Update nFilterIndex */
            mem.Write32(ofn_addr + 0x18, ofn.nFilterIndex);
            printf("[THUNK]   -> selected: '%ls'\n", native_file.data());
        } else {
            printf("[THUNK]   -> cancelled\n");
        }
        regs[0] = result;
        return true;
    };
    Thunk("GetOpenFileNameW", 488, [this, getFileNameImpl](uint32_t* regs, EmulatedMemory& mem) -> bool {
        return getFileNameImpl(regs, mem, false);
    });
    Thunk("GetSaveFileNameW", [this, getFileNameImpl](uint32_t* regs, EmulatedMemory& mem) -> bool {
        return getFileNameImpl(regs, mem, true);
    });
    /* COM */
    Thunk("CoInitializeEx", [](uint32_t* regs, EmulatedMemory&) -> bool {
        HRESULT hr = CoInitializeEx(NULL, regs[1]);
        printf("[THUNK] CoInitializeEx(0x%X) -> 0x%08X\n", regs[1], (uint32_t)hr);
        regs[0] = (uint32_t)hr;
        return true;
    });
    Thunk("CoUninitialize", [](uint32_t* regs, EmulatedMemory&) -> bool {
        CoUninitialize(); regs[0] = 0; return true;
    });
    /* Common controls */
    Thunk("InitCommonControlsEx", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* Read INITCOMMONCONTROLSEX from emulated memory: { DWORD dwSize; DWORD dwICC; } */
        uint32_t icc_addr = regs[0];
        INITCOMMONCONTROLSEX icc = {};
        icc.dwSize = sizeof(icc);
        icc.dwICC = icc_addr ? mem.Read32(icc_addr + 4) : ICC_WIN95_CLASSES;
        BOOL ret = InitCommonControlsEx(&icc);
        printf("[THUNK] InitCommonControlsEx(dwICC=0x%X) -> %d\n", icc.dwICC, ret);
        regs[0] = ret;
        return true;
    });
    Thunk("InitCommonControls", [](uint32_t* regs, EmulatedMemory&) -> bool {
        InitCommonControls(); regs[0] = 0; return true;
    });
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
    Thunk("ImageList_LoadImage", 758, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* ImageList_LoadImage(hInstance, lpbmp, cx, cGrow, crMask, uType, uFlags) */
        uint32_t hmod = regs[0], lpbmp = regs[1], cx = regs[2], cGrow = regs[3];
        COLORREF crMask = ReadStackArg(regs, mem, 0);
        UINT uType = ReadStackArg(regs, mem, 1);
        UINT uFlags = ReadStackArg(regs, mem, 2);
        printf("[THUNK] ImageList_LoadImage(0x%08X, %d, cx=%d, cGrow=%d, crMask=0x%X, type=%d, flags=0x%X)\n",
               hmod, lpbmp, cx, cGrow, crMask, uType, uFlags);
        HMODULE native_mod = NULL;
        bool is_arm = (hmod == emu_hinstance);
        for (auto& pair : loaded_dlls) { if (pair.second.base_addr == hmod) { is_arm = true; break; } }
        if (is_arm) native_mod = GetNativeModuleForResources(hmod);
        else native_mod = (HMODULE)(intptr_t)(int32_t)hmod;
        HIMAGELIST h = native_mod ? ImageList_LoadImageW(native_mod, MAKEINTRESOURCEW(lpbmp), cx, cGrow, crMask, uType, uFlags) : NULL;
        regs[0] = (uint32_t)(uintptr_t)h;
        return true;
    });
    Thunk("ImageList_GetIconSize", 755, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int cx, cy; BOOL ret = ImageList_GetIconSize((HIMAGELIST)(intptr_t)(int32_t)regs[0], &cx, &cy);
        if (regs[1]) mem.Write32(regs[1], cx); if (regs[2]) mem.Write32(regs[2], cy);
        regs[0] = ret; return true;
    });
    /* IMM stubs */
    Thunk("ImmAssociateContext", 770, stub0("ImmAssociateContext"));
    Thunk("ImmGetContext", 783, stub0("ImmGetContext"));
    Thunk("ImmReleaseContext", 803, stub0("ImmReleaseContext"));
    /* Process/thread stubs */
    Thunk("CreateThread", 492, stub0("CreateThread"));
    Thunk("CreateProcessW", 493, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* WinCE CreateProcessW(pszImageName, pszCmdLine, psaProcess, psaThread,
           fInheritHandles, fdwCreate, pvEnvironment, pszCurDir, psiStartInfo, pProcInfo) */
        uint32_t image_ptr = regs[0], cmdline_ptr = regs[1];
        uint32_t fdwCreate = ReadStackArg(regs, mem, 1);
        uint32_t curdir_ptr = ReadStackArg(regs, mem, 3);
        uint32_t procinfo_ptr = ReadStackArg(regs, mem, 5);
        std::wstring image, cmdline, curdir;
        if (image_ptr) image = ReadWStringFromEmu(mem, image_ptr);
        if (cmdline_ptr) cmdline = ReadWStringFromEmu(mem, cmdline_ptr);
        if (curdir_ptr) curdir = ReadWStringFromEmu(mem, curdir_ptr);
        printf("[THUNK] CreateProcessW(image='%ls', cmdline='%ls', curdir='%ls', flags=0x%X)\n",
               image.c_str(), cmdline.c_str(), curdir.c_str(), fdwCreate);
        STARTUPINFOW si = {}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi = {};
        /* Need mutable copy of cmdline for CreateProcessW */
        std::vector<wchar_t> cmdline_buf(cmdline.begin(), cmdline.end());
        cmdline_buf.push_back(0);
        BOOL ret = CreateProcessW(
            image.empty() ? NULL : image.c_str(),
            cmdline_buf.data(),
            NULL, NULL, FALSE, fdwCreate, NULL,
            curdir.empty() ? NULL : curdir.c_str(),
            &si, &pi);
        if (ret && procinfo_ptr) {
            /* Write PROCESS_INFORMATION back: hProcess, hThread, dwProcessId, dwThreadId */
            mem.Write32(procinfo_ptr + 0x00, (uint32_t)(uintptr_t)pi.hProcess);
            mem.Write32(procinfo_ptr + 0x04, (uint32_t)(uintptr_t)pi.hThread);
            mem.Write32(procinfo_ptr + 0x08, pi.dwProcessId);
            mem.Write32(procinfo_ptr + 0x0C, pi.dwThreadId);
        }
        printf("[THUNK]   -> %s (pid=%d)\n", ret ? "OK" : "FAILED", ret ? pi.dwProcessId : 0);
        regs[0] = ret;
        return true;
    });
    Thunk("TerminateThread", 491, stub0("TerminateThread"));
    Thunk("SetThreadPriority", 514, stub0("SetThreadPriority"));
    Thunk("GetExitCodeProcess", 519, stub0("GetExitCodeProcess"));
    Thunk("OpenProcess", 509, stub0("OpenProcess"));
    Thunk("WaitForMultipleObjects", 498, stub0("WaitForMultipleObjects"));
    Thunk("CreateFileMappingW", 548, stub0("CreateFileMappingW"));
    Thunk("MapViewOfFile", 549, stub0("MapViewOfFile"));
    Thunk("UnmapViewOfFile", 550, stub0("UnmapViewOfFile"));
    /* Ordinal-only entries (no handler, for logging) */
    Thunk("Shell_NotifyIcon", 481, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* Shell_NotifyIcon(dwMessage, pnid) */
        DWORD dwMessage = regs[0];
        uint32_t nid_addr = regs[1];
        if (!nid_addr) { regs[0] = 0; return true; }
        /* WinCE NOTIFYICONDATA (32-bit):
           0x00 cbSize, 0x04 hWnd, 0x08 uID, 0x0C uFlags,
           0x10 uCallbackMessage, 0x14 hIcon, 0x18 szTip[64] (128 bytes) */
        NOTIFYICONDATAW nid = {};
        nid.cbSize = sizeof(NOTIFYICONDATAW);
        nid.hWnd = (HWND)(intptr_t)(int32_t)mem.Read32(nid_addr + 0x04);
        nid.uID = mem.Read32(nid_addr + 0x08);
        nid.uFlags = mem.Read32(nid_addr + 0x0C);
        nid.uCallbackMessage = mem.Read32(nid_addr + 0x10);
        nid.hIcon = (HICON)(intptr_t)(int32_t)mem.Read32(nid_addr + 0x14);
        /* Read szTip (up to 64 wchars at offset 0x18) */
        for (int i = 0; i < 63; i++) {
            wchar_t c = (wchar_t)mem.Read16(nid_addr + 0x18 + i * 2);
            nid.szTip[i] = c;
            if (c == 0) break;
        }
        nid.szTip[63] = 0;
        printf("[THUNK] Shell_NotifyIcon(msg=%d, uID=%d, tip='%ls')\n",
               dwMessage, nid.uID, nid.szTip);
        BOOL ret = Shell_NotifyIconW(dwMessage, &nid);
        regs[0] = ret;
        return true;
    });
    ThunkOrdinal("SHCreateShortcut", 484);
    ThunkOrdinal("GetOwnerProcess", 606);
    ThunkOrdinal("Random", 80);
}
