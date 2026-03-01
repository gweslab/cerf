/* Win32 thunks: system info, time, sync, locale, registry, resources, misc */
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include <cstdio>
#include <algorithm>
#include <commctrl.h>
#include <vector>

bool Win32Thunks::ExecuteSystemThunk(const std::string& func, uint32_t* regs, EmulatedMemory& mem) {
    /* Error handling */
    if (func == "GetLastError") {
        regs[0] = GetLastError();
        return true;
    }
    if (func == "SetLastError") {
        SetLastError(regs[0]);
        return true;
    }
    if (func == "RaiseException") {
        printf("[THUNK] RaiseException(0x%08X) - ignoring\n", regs[0]);
        return true;
    }

    /* System info */
    if (func == "GetSystemMetrics") {
        int idx = (int)regs[0];
        if (idx == SM_CXSCREEN || idx == SM_CYSCREEN) {
            RECT work_area;
            SystemParametersInfoW(SPI_GETWORKAREA, 0, &work_area, 0);
            regs[0] = (idx == SM_CXSCREEN)
                ? (uint32_t)(work_area.right - work_area.left)
                : (uint32_t)(work_area.bottom - work_area.top);
            return true;
        }
        regs[0] = GetSystemMetrics(idx);
        return true;
    }
    if (func == "GetSysColor") {
        regs[0] = GetSysColor(regs[0]);
        return true;
    }
    if (func == "GetSysColorBrush") {
        regs[0] = (uint32_t)(uintptr_t)GetSysColorBrush(regs[0]);
        return true;
    }
    if (func == "GetTickCount") {
        regs[0] = GetTickCount();
        return true;
    }
    if (func == "GetSystemInfo") {
        if (regs[0]) {
            SYSTEM_INFO si;
            GetSystemInfo(&si);
            mem.Write32(regs[0] + 0, 0);    /* wProcessorArchitecture = ARM */
            mem.Write32(regs[0] + 4, si.dwPageSize);
            mem.Write32(regs[0] + 8, 0x10000);
            mem.Write32(regs[0] + 12, 0x7FFFFFFF);
            mem.Write32(regs[0] + 20, 1);
            mem.Write32(regs[0] + 24, 0x4);
        }
        return true;
    }

    /* Time functions */
    if (func == "Sleep") {
        Sleep(regs[0]);
        return true;
    }
    if (func == "GetLocalTime" || func == "GetSystemTime") {
        SYSTEMTIME st;
        if (func == "GetLocalTime") GetLocalTime(&st);
        else GetSystemTime(&st);
        if (regs[0]) {
            mem.Write16(regs[0] + 0, st.wYear);
            mem.Write16(regs[0] + 2, st.wMonth);
            mem.Write16(regs[0] + 4, st.wDayOfWeek);
            mem.Write16(regs[0] + 6, st.wDay);
            mem.Write16(regs[0] + 8, st.wHour);
            mem.Write16(regs[0] + 10, st.wMinute);
            mem.Write16(regs[0] + 12, st.wSecond);
            mem.Write16(regs[0] + 14, st.wMilliseconds);
        }
        return true;
    }

    /* Sync */
    if (func == "InitializeCriticalSection" || func == "DeleteCriticalSection" ||
        func == "EnterCriticalSection" || func == "LeaveCriticalSection") {
        return true;
    }
    if (func == "CreateEventW") {
        regs[0] = (uint32_t)(uintptr_t)CreateEventW(NULL, regs[1], regs[2], NULL);
        return true;
    }
    if (func == "WaitForSingleObject") {
        regs[0] = WaitForSingleObject((HANDLE)(intptr_t)(int32_t)regs[0], regs[1]);
        return true;
    }
    if (func == "CloseHandle") {
        regs[0] = CloseHandle((HANDLE)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "CreateMutexW") {
        regs[0] = (uint32_t)(uintptr_t)CreateMutexW(NULL, regs[1], NULL);
        return true;
    }
    if (func == "ReleaseMutex") {
        regs[0] = ReleaseMutex((HANDLE)(intptr_t)(int32_t)regs[0]);
        return true;
    }

    /* TLS */
    if (func == "TlsGetValue" || func == "TlsSetValue" || func == "TlsCall") {
        regs[0] = 0;
        return true;
    }

    /* Locale */
    if (func == "GetLocaleInfoW") {
        wchar_t buf[256] = {};
        uint32_t maxlen = regs[3];
        if (maxlen > 256) maxlen = 256;
        int ret = GetLocaleInfoW(regs[0], regs[1], buf, (int)maxlen);
        uint32_t dst = regs[2];
        for (int i = 0; i < ret; i++) mem.Write16(dst + i * 2, buf[i]);
        regs[0] = ret;
        return true;
    }
    if (func == "GetSystemDefaultLangID") {
        regs[0] = GetSystemDefaultLangID();
        return true;
    }
    if (func == "GetUserDefaultLCID") {
        regs[0] = GetUserDefaultLCID();
        return true;
    }
    if (func == "GetSystemDefaultLCID") {
        regs[0] = GetSystemDefaultLCID();
        return true;
    }
    if (func == "ConvertDefaultLocale") {
        regs[0] = ConvertDefaultLocale(regs[0]);
        return true;
    }
    if (func == "GetACP") {
        regs[0] = GetACP();
        return true;
    }
    if (func == "GetOEMCP") {
        regs[0] = GetOEMCP();
        return true;
    }
    if (func == "GetCPInfo") {
        regs[0] = 0; /* Stub */
        return true;
    }
    if (func == "LCMapStringW" || func == "GetTimeFormatW" || func == "GetDateFormatW") {
        regs[0] = 0; /* Stub */
        return true;
    }

    /* Registry stubs */
    if (func == "RegOpenKeyExW" || func == "RegCreateKeyExW") {
        printf("[THUNK] %s - stubbed (returning error)\n", func.c_str());
        regs[0] = ERROR_FILE_NOT_FOUND;
        return true;
    }
    if (func == "RegCloseKey") {
        regs[0] = 0;
        return true;
    }
    if (func == "RegQueryValueExW" || func == "RegSetValueExW" ||
        func == "RegDeleteKeyW" || func == "RegEnumValueW" || func == "RegQueryInfoKeyW") {
        regs[0] = ERROR_FILE_NOT_FOUND;
        return true;
    }

    /* Resources */
    if (func == "LoadStringW") {
        uint32_t hmod = regs[0];
        uint32_t str_id = regs[1];
        uint32_t dst = regs[2];
        uint32_t maxlen = regs[3];
        if (maxlen > 4096) maxlen = 4096;

        uint32_t bundle_id = (str_id / 16) + 1;
        uint32_t string_idx = str_id % 16;

        uint32_t rsrc_rva = 0, rsrc_sz = 0;
        bool is_arm = false;
        if (hmod == emu_hinstance || hmod == 0) {
            is_arm = true;
            uint32_t base = emu_hinstance;
            uint32_t dos_lfanew = mem.Read32(base + 0x3C);
            uint32_t nt_addr = base + dos_lfanew;
            uint32_t num_rva_sizes = mem.Read32(nt_addr + 0x74);
            if (num_rva_sizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
                rsrc_rva = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8);
                rsrc_sz = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8 + 4);
            }
            hmod = base;
        }
        for (auto& pair : loaded_dlls) {
            if (pair.second.base_addr == hmod) {
                is_arm = true;
                rsrc_rva = pair.second.pe_info.rsrc_rva;
                rsrc_sz = pair.second.pe_info.rsrc_size;
                break;
            }
        }

        if (is_arm && rsrc_rva) {
            uint32_t data_rva = 0, data_size = 0;
            if (FindResourceInPE(hmod, rsrc_rva, rsrc_sz, 6, bundle_id, data_rva, data_size)) {
                uint8_t* data = mem.Translate(hmod + data_rva);
                if (data) {
                    uint16_t* p = (uint16_t*)data;
                    for (uint32_t i = 0; i < string_idx && (uint8_t*)p < data + data_size; i++) {
                        uint16_t len = *p++;
                        p += len;
                    }
                    if ((uint8_t*)p < data + data_size) {
                        uint16_t len = *p++;
                        uint32_t copy_len = (len < maxlen - 1) ? len : maxlen - 1;
                        for (uint32_t i = 0; i < copy_len; i++) {
                            mem.Write16(dst + i * 2, p[i]);
                        }
                        mem.Write16(dst + copy_len * 2, 0);
                        regs[0] = copy_len;
                        printf("[THUNK] LoadStringW(0x%08X, %u) -> %u chars\n", hmod, str_id, copy_len);
                        return true;
                    }
                }
            }
            if (dst && maxlen > 0) mem.Write16(dst, 0);
            regs[0] = 0;
            printf("[THUNK] LoadStringW(0x%08X, %u) -> not found\n", hmod, str_id);
        } else {
            wchar_t buf[1024] = {};
            if (maxlen > 1024) maxlen = 1024;
            int ret = LoadStringW(GetModuleHandleW(NULL), str_id, buf, (int)maxlen);
            for (int i = 0; i <= ret && i < (int)maxlen; i++) {
                mem.Write16(dst + i * 2, buf[i]);
            }
            regs[0] = ret;
        }
        return true;
    }
    if (func == "LoadBitmapW") {
        uint32_t hmod = regs[0];
        uint32_t name_id = regs[1];

        bool is_arm_module = (hmod == emu_hinstance);
        for (auto& pair : loaded_dlls) {
            if (pair.second.base_addr == hmod) { is_arm_module = true; break; }
        }

        if (is_arm_module) {
            uint32_t rsrc_rva = 0, rsrc_sz = 0;
            if (hmod == emu_hinstance) {
                uint32_t dos_lfanew = mem.Read32(hmod + 0x3C);
                uint32_t nt_addr = hmod + dos_lfanew;
                uint32_t num_rva_sizes = mem.Read32(nt_addr + 0x74);
                if (num_rva_sizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
                    rsrc_rva = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8);
                    rsrc_sz = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8 + 4);
                }
            }
            for (auto& pair : loaded_dlls) {
                if (pair.second.base_addr == hmod) {
                    rsrc_rva = pair.second.pe_info.rsrc_rva;
                    rsrc_sz = pair.second.pe_info.rsrc_size;
                    break;
                }
            }

            uint32_t data_rva = 0, data_size = 0;
            if (rsrc_rva && FindResourceInPE(hmod, rsrc_rva, rsrc_sz,
                                             (uint32_t)RT_BITMAP, name_id, data_rva, data_size)) {
                uint8_t* bmp_data = mem.Translate(hmod + data_rva);
                if (bmp_data && data_size > sizeof(BITMAPINFOHEADER)) {
                    BITMAPINFO* bmi = (BITMAPINFO*)bmp_data;
                    HDC hdc = GetDC(NULL);
                    int colors = 0;
                    if (bmi->bmiHeader.biBitCount <= 8)
                        colors = (bmi->bmiHeader.biClrUsed ? bmi->bmiHeader.biClrUsed : (1 << bmi->bmiHeader.biBitCount));
                    uint8_t* bits = bmp_data + sizeof(BITMAPINFOHEADER) + colors * sizeof(RGBQUAD);
                    HBITMAP hbm = CreateDIBitmap(hdc, &bmi->bmiHeader, CBM_INIT,
                                                  bits, bmi, DIB_RGB_COLORS);
                    ReleaseDC(NULL, hdc);
                    regs[0] = (uint32_t)(uintptr_t)hbm;
                    printf("[THUNK] LoadBitmapW(0x%08X, %u) -> HBITMAP=%p (from PE rsrc)\n",
                           hmod, name_id, hbm);
                } else {
                    regs[0] = 0;
                }
            } else {
                printf("[THUNK] LoadBitmapW(0x%08X, %u) -> resource not found\n", hmod, name_id);
                regs[0] = 0;
            }
        } else {
            regs[0] = (uint32_t)(uintptr_t)LoadBitmapW((HINSTANCE)(intptr_t)(int32_t)hmod,
                                                         MAKEINTRESOURCEW(name_id));
        }
        return true;
    }
    if (func == "LoadImageW") {
        uint32_t hmod = regs[0];
        uint32_t name_id = regs[1];
        uint32_t type = regs[2];
        int cx = (int)regs[3];
        int cy = (int)ReadStackArg(regs, mem, 0);
        uint32_t fuLoad = ReadStackArg(regs, mem, 1);

        /* Check if this is an ARM module */
        bool is_arm_module = (hmod == emu_hinstance);
        for (auto& pair : loaded_dlls) {
            if (pair.second.base_addr == hmod) { is_arm_module = true; break; }
        }

        if (is_arm_module && type == IMAGE_BITMAP) {
            /* Load bitmap from ARM PE resources (same as LoadBitmapW) */
            uint32_t rsrc_rva = 0, rsrc_sz = 0;
            if (hmod == emu_hinstance) {
                uint32_t dos_lfanew = mem.Read32(hmod + 0x3C);
                uint32_t nt_addr = hmod + dos_lfanew;
                uint32_t num_rva_sizes = mem.Read32(nt_addr + 0x74);
                if (num_rva_sizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
                    rsrc_rva = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8);
                    rsrc_sz = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8 + 4);
                }
            }
            for (auto& pair : loaded_dlls) {
                if (pair.second.base_addr == hmod) {
                    rsrc_rva = pair.second.pe_info.rsrc_rva;
                    rsrc_sz = pair.second.pe_info.rsrc_size;
                    break;
                }
            }

            uint32_t data_rva = 0, data_size = 0;
            if (rsrc_rva && FindResourceInPE(hmod, rsrc_rva, rsrc_sz,
                                             (uint32_t)RT_BITMAP, name_id, data_rva, data_size)) {
                uint8_t* bmp_data = mem.Translate(hmod + data_rva);
                if (bmp_data && data_size > sizeof(BITMAPINFOHEADER)) {
                    BITMAPINFO* bmi = (BITMAPINFO*)bmp_data;
                    HDC hdc = GetDC(NULL);
                    int colors = 0;
                    if (bmi->bmiHeader.biBitCount <= 8)
                        colors = (bmi->bmiHeader.biClrUsed ? bmi->bmiHeader.biClrUsed : (1 << bmi->bmiHeader.biBitCount));
                    uint8_t* bits = bmp_data + sizeof(BITMAPINFOHEADER) + colors * sizeof(RGBQUAD);
                    HBITMAP hbm = CreateDIBitmap(hdc, &bmi->bmiHeader, CBM_INIT,
                                                  bits, bmi, DIB_RGB_COLORS);
                    ReleaseDC(NULL, hdc);
                    regs[0] = (uint32_t)(uintptr_t)hbm;
                    printf("[THUNK] LoadImageW(0x%08X, %u, IMAGE_BITMAP) -> HBITMAP=%p (from PE rsrc)\n",
                           hmod, name_id, hbm);
                } else {
                    regs[0] = 0;
                }
            } else {
                printf("[THUNK] LoadImageW(0x%08X, %u, IMAGE_BITMAP) -> resource not found\n",
                       hmod, name_id);
                regs[0] = 0;
            }
        } else if (!is_arm_module || hmod == 0) {
            /* Non-ARM module or NULL (system resource) - use native API */
            regs[0] = (uint32_t)(uintptr_t)LoadImageW(
                (HINSTANCE)(intptr_t)(int32_t)hmod,
                MAKEINTRESOURCEW(name_id), type, cx, cy, fuLoad);
        } else {
            /* ARM module with non-bitmap type - stub */
            printf("[THUNK] LoadImageW(0x%08X, %u, type=%u) -> unsupported type for ARM module\n",
                   hmod, name_id, type);
            regs[0] = 0;
        }
        return true;
    }
    if (func == "FindResourceW") {
        uint32_t hmod = regs[0];
        uint32_t name_arg = regs[1];
        uint32_t type_arg = regs[2];

        uint32_t rsrc_rva = 0, rsrc_sz = 0;
        if (hmod == emu_hinstance) {
            uint32_t dos_lfanew = mem.Read32(hmod + 0x3C);
            uint32_t nt_addr = hmod + dos_lfanew;
            uint32_t num_rva_sizes = mem.Read32(nt_addr + 0x74);
            if (num_rva_sizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
                rsrc_rva = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8);
                rsrc_sz = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8 + 4);
            }
        }
        for (auto& pair : loaded_dlls) {
            if (pair.second.base_addr == hmod) {
                rsrc_rva = pair.second.pe_info.rsrc_rva;
                rsrc_sz = pair.second.pe_info.rsrc_size;
                break;
            }
        }

        uint32_t data_rva = 0, data_size = 0;
        if (rsrc_rva && FindResourceInPE(hmod, rsrc_rva, rsrc_sz,
                                         type_arg, name_arg, data_rva, data_size)) {
            uint32_t fake = next_rsrc_handle++;
            rsrc_map[fake] = { data_rva, data_size, hmod };
            regs[0] = fake;
            printf("[THUNK] FindResourceW(0x%08X, %u, %u) -> 0x%08X (rva=0x%X, size=%u)\n",
                   hmod, name_arg, type_arg, fake, data_rva, data_size);
        } else {
            printf("[THUNK] FindResourceW(0x%08X, %u, %u) -> NOT FOUND\n",
                   hmod, name_arg, type_arg);
            regs[0] = 0;
        }
        return true;
    }
    if (func == "LoadResource") {
        uint32_t hrsrc_emu = regs[1];
        auto it = rsrc_map.find(hrsrc_emu);
        if (it != rsrc_map.end()) {
            uint32_t addr = it->second.module_base + it->second.data_rva;
            regs[0] = addr;
            printf("[THUNK] LoadResource -> 0x%08X (%u bytes)\n", addr, it->second.data_size);
        } else {
            regs[0] = 0;
        }
        return true;
    }
    if (func == "SizeofResource") {
        uint32_t hrsrc_emu = regs[1];
        auto it = rsrc_map.find(hrsrc_emu);
        if (it != rsrc_map.end()) {
            regs[0] = it->second.data_size;
        } else {
            regs[0] = 0;
        }
        return true;
    }
    if (func == "FreeLibrary") {
        regs[0] = 1;
        return true;
    }

    /* Debug */
    if (func == "OutputDebugStringW") {
        std::wstring msg = ReadWStringFromEmu(mem, regs[0]);
        printf("[DEBUG] %ls\n", msg.c_str());
        return true;
    }
    if (func == "NKDbgPrintfW") {
        std::wstring msg = ReadWStringFromEmu(mem, regs[0]);
        printf("[NKDbg] %ls\n", msg.c_str());
        return true;
    }

    /* File I/O stubs */
    if (func == "CreateFileW") {
        std::wstring path = ReadWStringFromEmu(mem, regs[0]);
        printf("[THUNK] CreateFileW('%ls') - stub\n", path.c_str());
        regs[0] = (uint32_t)INVALID_HANDLE_VALUE;
        return true;
    }

    /* Process info */
    if (func == "GetProcessVersion") {
        regs[0] = 0x0400000A;
        return true;
    }
    if (func == "GetOwnerProcess") {
        regs[0] = GetCurrentProcessId();
        return true;
    }
    if (func == "GetStartupInfoW") {
        for (int i = 0; i < 68; i += 4) mem.Write32(regs[0] + i, 0);
        mem.Write32(regs[0], 68);
        return true;
    }

    /* Stubs for misc functions */
    if (func == "DisableThreadLibraryCalls") { regs[0] = 1; return true; }
    if (func == "FlushInstructionCache") { regs[0] = 1; return true; }
    if (func == "GetProcessIndexFromID") { regs[0] = 1; return true; }
    if (func == "GlobalMemoryStatus") {
        uint32_t ptr = regs[0];
        if (ptr) {
            MEMORYSTATUS ms = {};
            ms.dwLength = sizeof(ms);
            GlobalMemoryStatus(&ms);
            mem.Write32(ptr + 0,  32);
            mem.Write32(ptr + 4,  ms.dwMemoryLoad);
            mem.Write32(ptr + 8,  (uint32_t)std::min(ms.dwTotalPhys,    (SIZE_T)UINT32_MAX));
            mem.Write32(ptr + 12, (uint32_t)std::min(ms.dwAvailPhys,    (SIZE_T)UINT32_MAX));
            mem.Write32(ptr + 16, (uint32_t)std::min(ms.dwTotalPageFile, (SIZE_T)UINT32_MAX));
            mem.Write32(ptr + 20, (uint32_t)std::min(ms.dwAvailPageFile, (SIZE_T)UINT32_MAX));
            mem.Write32(ptr + 24, (uint32_t)std::min(ms.dwTotalVirtual,  (SIZE_T)UINT32_MAX));
            mem.Write32(ptr + 28, (uint32_t)std::min(ms.dwAvailVirtual,  (SIZE_T)UINT32_MAX));
        }
        return true;
    }
    if (func == "GetVersionExW") {
        if (regs[0]) {
            mem.Write32(regs[0] + 4, 4);
            mem.Write32(regs[0] + 8, 21);
            mem.Write32(regs[0] + 12, 0);
            mem.Write32(regs[0] + 16, 0);
        }
        regs[0] = 1;
        return true;
    }
    if (func == "SystemParametersInfoW") {
        regs[0] = SystemParametersInfoW(regs[0], regs[1], NULL, regs[3]);
        return true;
    }

    /* Gesture stubs */
    if (func == "RegisterDefaultGestureHandler" || func == "GetGestureInfo" ||
        func == "GetGestureExtraArguments" || func == "CloseGestureInfoHandle") {
        regs[0] = 0;
        return true;
    }

    /* Shell stubs */
    if (func == "SHGetSpecialFolderPath") { regs[0] = 0; return true; }
    if (func == "ShellExecuteEx") { regs[0] = 0; return true; }
    if (func == "SHLoadDIBitmap") { regs[0] = 0; return true; }

    /* Common controls */
    if (func == "ImageList_Create") {
        regs[0] = (uint32_t)(uintptr_t)ImageList_Create(regs[0], regs[1], regs[2], regs[3],
                                                         ReadStackArg(regs, mem, 0));
        return true;
    }
    if (func == "ImageList_Destroy") {
        regs[0] = ImageList_Destroy((HIMAGELIST)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "ImageList_Add") {
        regs[0] = ImageList_Add((HIMAGELIST)(intptr_t)(int32_t)regs[0],
                                (HBITMAP)(intptr_t)(int32_t)regs[1], (HBITMAP)(intptr_t)(int32_t)regs[2]);
        return true;
    }
    if (func == "ImageList_Draw") {
        regs[0] = ImageList_Draw((HIMAGELIST)(intptr_t)(int32_t)regs[0], regs[1],
                                 (HDC)(intptr_t)(int32_t)regs[2], regs[3],
                                 ReadStackArg(regs, mem, 0), ReadStackArg(regs, mem, 1));
        return true;
    }
    if (func == "ImageList_DrawEx") {
        regs[0] = ImageList_DrawEx((HIMAGELIST)(intptr_t)(int32_t)regs[0], regs[1],
                                    (HDC)(intptr_t)(int32_t)regs[2], regs[3],
                                    ReadStackArg(regs, mem, 0), ReadStackArg(regs, mem, 1),
                                    ReadStackArg(regs, mem, 2), ReadStackArg(regs, mem, 3),
                                    ReadStackArg(regs, mem, 4), ReadStackArg(regs, mem, 5));
        return true;
    }
    if (func == "ImageList_GetImageCount") {
        regs[0] = ImageList_GetImageCount((HIMAGELIST)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "ImageList_GetIconSize") {
        int cx, cy;
        BOOL ret = ImageList_GetIconSize((HIMAGELIST)(intptr_t)(int32_t)regs[0], &cx, &cy);
        if (regs[1]) mem.Write32(regs[1], cx);
        if (regs[2]) mem.Write32(regs[2], cy);
        regs[0] = ret;
        return true;
    }

    /* IMM stubs */
    if (func == "ImmAssociateContext" || func == "ImmGetContext" || func == "ImmReleaseContext") {
        regs[0] = 0;
        return true;
    }

    /* Clipboard stubs */
    if (func == "OpenClipboard") { regs[0] = 1; return true; }
    if (func == "CloseClipboard") { regs[0] = 1; return true; }
    if (func == "EmptyClipboard") { regs[0] = 1; return true; }
    if (func == "GetClipboardData") { regs[0] = 0; return true; }
    if (func == "SetClipboardData") { regs[0] = 0; return true; }
    if (func == "IsClipboardFormatAvailable") { regs[0] = 0; return true; }
    if (func == "EnumClipboardFormats") { regs[0] = 0; return true; }

    /* Caret stubs */
    if (func == "CreateCaret" || func == "HideCaret" || func == "ShowCaret") {
        regs[0] = 1;
        return true;
    }

    /* Cursor stubs */
    if (func == "CreateCursor" || func == "DestroyCursor" || func == "DestroyIcon" ||
        func == "DrawIconEx" || func == "ClipCursor" || func == "GetClipCursor" ||
        func == "GetCursor" || func == "SetCursorPos" || func == "ShowCursor") {
        regs[0] = 0;
        return true;
    }

    /* Sound stubs */
    if (func == "sndPlaySoundW") {
        regs[0] = 1;
        return true;
    }

    /* Ras stubs */
    if (func == "RasDial" || func == "RasHangup" || func == "RasHangUp") {
        regs[0] = 0;
        return true;
    }

    /* C runtime stubs */
    if (func == "_purecall") {
        printf("[THUNK] _purecall - abort\n");
        regs[0] = 0;
        return true;
    }
    if (func == "terminate") {
        printf("[THUNK] terminate() called\n");
        ExitProcess(3);
        return true;
    }
    if (func == "__security_gen_cookie" || func == "__security_gen_cookie2") {
        regs[0] = 0xBB40E64E;
        return true;
    }
    if (func == "CeGenRandom") {
        uint32_t len = regs[0];
        uint32_t buf = regs[1];
        for (uint32_t i = 0; i < len; i++)
            mem.Write8(buf + i, (uint8_t)(rand() & 0xFF));
        regs[0] = 1;
        return true;
    }
    if (func == "MulDiv") {
        regs[0] = MulDiv((int)regs[0], (int)regs[1], (int)regs[2]);
        return true;
    }
    if (func == "GetAPIAddress") { regs[0] = 0; return true; }
    if (func == "WaitForAPIReady") { regs[0] = 0; return true; }
    if (func == "__GetUserKData") { regs[0] = 0; return true; }
    if (func == "EventModify") { regs[0] = 1; return true; }
    if (func == "GlobalAddAtomW") { regs[0] = 1; return true; }
    if (func == "_setjmp3" || func == "_except_handler4_common") { regs[0] = 0; return true; }

    /* Platform-specific ordinals */
    if (func == "__PlatformSpecific2005" || func == "__PlatformSpecific2008") {
        regs[0] = 0;
        return true;
    }

    /* Process/thread stubs */
    if (func == "CreateThread" || func == "CreateProcessW" || func == "TerminateThread" ||
        func == "SetThreadPriority" || func == "GetExitCodeProcess" || func == "OpenProcess" ||
        func == "WaitForMultipleObjects" || func == "CreateFileMappingW" ||
        func == "MapViewOfFile" || func == "UnmapViewOfFile") {
        regs[0] = 0;
        return true;
    }

    return false;
}
