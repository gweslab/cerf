#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Shell thunks: ShellExecuteEx, Shell_NotifyIcon, SHGetSpecialFolderPath,
   GetOpenFileNameW/GetSaveFileNameW (coredll re-exports from commdlg),
   SH* functions (coredll re-exports from ceshell/aygshell) */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <shellapi.h>
#include <shlobj.h>

void Win32Thunks::RegisterShellHandlers() {
    auto stub0 = [](const char* name) -> ThunkHandler {
        return [name](uint32_t* regs, EmulatedMemory&) -> bool {
            LOG(THUNK, "[THUNK] [STUB] %s -> 0\n", name); regs[0] = 0; return true;
        };
    };
    /* Helper: forward a coredll re-export to the real ARM DLL.
       This mirrors what real coredll does: LoadLibrary + GetProcAddress + call. */
    auto forwardToArm = [this](const char* dll, const char* func, int nargs) -> ThunkHandler {
        return [this, dll, func, nargs](uint32_t* regs, EmulatedMemory& mem) -> bool {
            LoadedDll* mod = LoadArmDll(dll);
            if (mod && callback_executor) {
                uint32_t addr = PELoader::ResolveExportName(mem, mod->pe_info, func);
                if (addr) {
                    LOG(THUNK, "[THUNK] %s -> forwarding to ARM %s!%s @ 0x%08X\n", func, dll, func, addr);
                    uint32_t args[8] = {};
                    for (int i = 0; i < nargs && i < 4; i++) args[i] = regs[i];
                    for (int i = 4; i < nargs; i++) args[i] = ReadStackArg(regs, mem, i - 4);
                    regs[0] = callback_executor(addr, args, nargs);
                    return true;
                }
            }
            LOG(THUNK, "[THUNK] %s -> %s not available, stub returning 0\n", func, dll);
            regs[0] = 0;
            return true;
        };
    };
    /* SHGetSpecialFolderPath(hwnd, lpszPath, csidl, fCreate) — coredll kernel API, not in ceshell.
       Returns WinCE-style paths (e.g. \My Documents) since the ARM ceshell code expects
       WinCE path conventions. MapWinCEPath maps these back to real host directories. */
    Thunk("SHGetSpecialFolderPath", 295, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t path_ptr = regs[1];
        int csidl = (int)regs[2];
        bool fCreate = regs[3] != 0;
        LOG(THUNK, "[THUNK] SHGetSpecialFolderPath(hwnd=0x%08X, csidl=%d, fCreate=%d)\n", regs[0], csidl, fCreate);
        /* Map CSIDL to WinCE-style paths */
        const wchar_t* wce_path = nullptr;
        switch (csidl & 0xFF) { /* mask off CSIDL_FLAG_CREATE etc. */
            case 0x05: wce_path = L"\\My Documents"; break;  /* CSIDL_PERSONAL */
            case 0x10: wce_path = L"\\Windows\\Desktop"; break; /* CSIDL_DESKTOPDIRECTORY */
            case 0x02: wce_path = L"\\Windows\\Programs"; break; /* CSIDL_PROGRAMS */
            case 0x07: wce_path = L"\\Windows\\StartUp"; break;  /* CSIDL_STARTUP */
            case 0x06: wce_path = L"\\Windows\\Favorites"; break; /* CSIDL_FAVORITES */
            case 0x14: wce_path = L"\\Windows\\Fonts"; break;     /* CSIDL_FONTS */
            case 0x24: wce_path = L"\\Windows"; break;             /* CSIDL_WINDOWS */
            case 0x1A: wce_path = L"\\Application Data"; break;   /* CSIDL_APPDATA */
            case 0x1C: wce_path = L"\\Application Data"; break;   /* CSIDL_LOCAL_APPDATA */
            case 0x27: wce_path = L"\\My Documents"; break;       /* CSIDL_MYPICTURES */
            default: break;
        }
        if (wce_path && path_ptr) {
            size_t len = wcslen(wce_path);
            for (size_t i = 0; i <= len; i++)
                mem.Write16(path_ptr + (uint32_t)i * 2, wce_path[i]);
            if (fCreate) {
                std::wstring host_path = MapWinCEPath(wce_path);
                CreateDirectoryW(host_path.c_str(), NULL); /* ensure it exists */
            }
            LOG(THUNK, "[THUNK]   -> '%ls'\n", wce_path);
            regs[0] = 1;
        } else if (path_ptr) {
            /* Unknown CSIDL — try native */
            wchar_t path[MAX_PATH] = {};
            HRESULT hr = SHGetFolderPathW(NULL, csidl, NULL, 0, path);
            if (SUCCEEDED(hr)) {
                for (int i = 0; i < MAX_PATH; i++) {
                    mem.Write16(path_ptr + i * 2, path[i]);
                    if (path[i] == 0) break;
                }
                LOG(THUNK, "[THUNK]   -> '%ls' (native fallback)\n", path);
                regs[0] = 1;
            } else {
                LOG(THUNK, "[THUNK]   -> FAILED (csidl=%d)\n", csidl);
                mem.Write16(path_ptr, 0);
                regs[0] = 0;
            }
        } else {
            regs[0] = 0;
        }
        return true;
    });
    /* SHLoadDIBitmap(lpszFileName) — load a BMP file and return HBITMAP.
       ceshell.dll's export is a PE forwarder back to COREDLL (circular),
       so we implement it natively.  Handles standard .bmp and WinCE .2bp files. */
    Thunk("SHLoadDIBitmap", 487, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring wce_path = ReadWStringFromEmu(mem, regs[0]);
        std::wstring host_path = MapWinCEPath(wce_path);
        LOG(THUNK, "[THUNK] SHLoadDIBitmap('%ls' -> '%ls')\n", wce_path.c_str(), host_path.c_str());
        HANDLE hFile = CreateFileW(host_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            LOG(THUNK, "[THUNK]   -> file not found\n");
            regs[0] = 0;
            return true;
        }
        DWORD fileSize = GetFileSize(hFile, NULL);
        std::vector<uint8_t> buf(fileSize);
        DWORD bytesRead = 0;
        ReadFile(hFile, buf.data(), fileSize, &bytesRead, NULL);
        CloseHandle(hFile);
        if (bytesRead < sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER)) {
            LOG(THUNK, "[THUNK]   -> file too small (%u bytes)\n", bytesRead);
            regs[0] = 0;
            return true;
        }
        BITMAPFILEHEADER* bfh = (BITMAPFILEHEADER*)buf.data();
        BITMAPINFO* bmi = (BITMAPINFO*)(buf.data() + sizeof(BITMAPFILEHEADER));
        uint8_t* bits = buf.data() + bfh->bfOffBits;
        HBITMAP hbm = NULL;
        HDC hdc = GetDC(NULL);
        if (bmi->bmiHeader.biBitCount == 2) {
            /* WinCE 2bpp format — desktop Windows doesn't support it.
               Convert to 4bpp: expand each 2-bit pixel to 4 bits. */
            int w = bmi->bmiHeader.biWidth, h = abs(bmi->bmiHeader.biHeight);
            int src_stride = ((w * 2 + 31) / 32) * 4;
            int dst_stride = ((w * 4 + 31) / 32) * 4;
            std::vector<uint8_t> dst_bits(dst_stride * h, 0);
            for (int y = 0; y < h; y++) {
                uint8_t* src_row = bits + y * src_stride;
                uint8_t* dst_row = dst_bits.data() + y * dst_stride;
                for (int x = 0; x < w; x++) {
                    int src_byte = x / 4, src_shift = 6 - (x % 4) * 2;
                    uint8_t val = (src_row[src_byte] >> src_shift) & 0x3;
                    int dst_byte = x / 2, dst_shift = (x % 2 == 0) ? 4 : 0;
                    dst_row[dst_byte] |= (val << dst_shift);
                }
            }
            /* Build 4bpp BITMAPINFO with same color table */
            int nColors = (bmi->bmiHeader.biClrUsed > 0) ? bmi->bmiHeader.biClrUsed : 4;
            std::vector<uint8_t> bmi4_buf(sizeof(BITMAPINFOHEADER) + nColors * sizeof(RGBQUAD));
            BITMAPINFO* bmi4 = (BITMAPINFO*)bmi4_buf.data();
            bmi4->bmiHeader = bmi->bmiHeader;
            bmi4->bmiHeader.biBitCount = 4;
            bmi4->bmiHeader.biSizeImage = dst_stride * h;
            bmi4->bmiHeader.biClrUsed = nColors;
            memcpy(bmi4->bmiColors, bmi->bmiColors, nColors * sizeof(RGBQUAD));
            hbm = CreateDIBitmap(hdc, &bmi4->bmiHeader, CBM_INIT, dst_bits.data(), bmi4, DIB_RGB_COLORS);
        } else {
            hbm = CreateDIBitmap(hdc, &bmi->bmiHeader, CBM_INIT, bits, bmi, DIB_RGB_COLORS);
        }
        ReleaseDC(NULL, hdc);
        LOG(THUNK, "[THUNK]   -> hbm=%p (%dx%d %dbpp)\n", hbm,
            bmi->bmiHeader.biWidth, bmi->bmiHeader.biHeight, bmi->bmiHeader.biBitCount);
        regs[0] = (uint32_t)(uintptr_t)hbm;
        return true;
    });
    /* SHCreateShortcut(lpszShortcut, lpszTarget) — forward to ceshell.dll */
    Thunk("SHCreateShortcut", 484, forwardToArm("ceshell.dll", "SHCreateShortcut", 2));
    /* SHCreateShortcutEx(lpszShortcut, lpszTarget, lpszParams) — forward to ceshell.dll */
    Thunk("SHCreateShortcutEx", forwardToArm("ceshell.dll", "SHCreateShortcutEx", 3));
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
        LOG(THUNK, "[THUNK] ShellExecuteEx(verb='%ls', file='%ls', params='%ls', dir='%ls', nShow=%d)\n",
               verb.c_str(), file.c_str(), params.c_str(), dir.c_str(), nShow);
        SHELLEXECUTEINFOW native_sei = {};
        native_sei.cbSize = sizeof(SHELLEXECUTEINFOW);
        native_sei.fMask = fMask;
        native_sei.hwnd = (HWND)(intptr_t)(int32_t)hwnd_val;
        std::wstring mapped_file = file.empty() ? L"" : MapWinCEPath(file);
        std::wstring mapped_dir = dir.empty() ? L"" : MapWinCEPath(dir);
        native_sei.lpVerb = verb.empty() ? NULL : verb.c_str();
        native_sei.lpFile = mapped_file.empty() ? NULL : mapped_file.c_str();
        native_sei.lpParameters = params.empty() ? NULL : params.c_str();
        native_sei.lpDirectory = mapped_dir.empty() ? NULL : mapped_dir.c_str();
        native_sei.nShow = nShow;
        BOOL ret = ShellExecuteExW(&native_sei);
        mem.Write32(sei_addr + 0x20, (uint32_t)(uintptr_t)native_sei.hInstApp);
        if (fMask & SEE_MASK_NOCLOSEPROCESS)
            mem.Write32(sei_addr + 0x38, (uint32_t)(uintptr_t)native_sei.hProcess);
        LOG(THUNK, "[THUNK]   -> %s\n", ret ? "OK" : "FAILED");
        regs[0] = ret;
        return true;
    });
    Thunk("Shell_NotifyIcon", 481, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
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
        for (int i = 0; i < 63; i++) {
            wchar_t c = (wchar_t)mem.Read16(nid_addr + 0x18 + i * 2);
            nid.szTip[i] = c;
            if (c == 0) break;
        }
        nid.szTip[63] = 0;
        LOG(THUNK, "[THUNK] Shell_NotifyIcon(msg=%d, uID=%d, tip='%ls')\n",
               dwMessage, nid.uID, nid.szTip);
        BOOL ret = Shell_NotifyIconW(dwMessage, &nid);
        regs[0] = ret;
        return true;
    });
    /* SHGetFileInfo(pszPath, dwFileAttributes, psfi, cbFileInfo, uFlags) — forward to ceshell.dll */
    Thunk("SHGetFileInfo", 482, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t pszPath_ptr = regs[0], dwFileAttrs = regs[1], psfi = regs[2];
        uint32_t cbFileInfo = regs[3], uFlags = ReadStackArg(regs, mem, 0);
        std::wstring path = pszPath_ptr ? ReadWStringFromEmu(mem, pszPath_ptr) : L"(null)";
        LOG(THUNK, "[THUNK] SHGetFileInfo('%ls', attrs=0x%X, psfi=0x%08X, cb=%d, flags=0x%04X)\n",
            path.c_str(), dwFileAttrs, psfi, cbFileInfo, uFlags);
        LoadedDll* mod = LoadArmDll("ceshell.dll");
        if (mod && callback_executor) {
            uint32_t addr = PELoader::ResolveExportName(mem, mod->pe_info, "SHGetFileInfo");
            if (addr) {
                uint32_t args[5] = { regs[0], regs[1], regs[2], regs[3], uFlags };
                regs[0] = callback_executor(addr, args, 5);
                LOG(THUNK, "[THUNK]   -> returned 0x%08X (iIcon=%d)\n",
                    regs[0], psfi ? (int)mem.Read32(psfi + 4) : -1);
                return true;
            }
        }
        LOG(THUNK, "[THUNK]   -> ceshell.dll not available, returning 0\n");
        regs[0] = 0;
        return true;
    });
    /* GetOpenFileNameW / GetSaveFileNameW — coredll forwards to ceshell!SHGetOpenFileName.
       In real coredll, both Open and Save go through SHGetOpenFileName in ceshell.dll. */
    Thunk("GetOpenFileNameW", 488, forwardToArm("ceshell.dll", "SHGetOpenFileName", 1));
    Thunk("GetSaveFileNameW", 489, forwardToArm("ceshell.dll", "SHGetOpenFileName", 1));
    /* ceshell re-exports via coredll */
    /* SHGetShortcutTarget(lpszShortcut, lpszTarget, cbMax) — forward to ceshell.dll */
    Thunk("SHGetShortcutTarget", 485, forwardToArm("ceshell.dll", "SHGetShortcutTarget", 3));
    /* SHShowOutOfMemory(hwndOwner, grfFlags) — forward to ceshell.dll */
    Thunk("SHShowOutOfMemory", forwardToArm("ceshell.dll", "SHShowOutOfMemory", 2));
    /* SHAddToRecentDocs(uFlags, pv) — forward to ceshell.dll */
    Thunk("SHAddToRecentDocs", 483, forwardToArm("ceshell.dll", "SHAddToRecentDocs", 2));
    /* SHGetSpecialFolderLocation(hwnd, csidl, ppidl) — forward to ceshell.dll */
    Thunk("SHGetSpecialFolderLocation", forwardToArm("ceshell.dll", "SHGetSpecialFolderLocation", 3));
    /* SHGetMalloc(ppMalloc) — forward to ceshell.dll */
    Thunk("SHGetMalloc", forwardToArm("ceshell.dll", "SHGetMalloc", 1));
    /* SHGetPathFromIDList(pidl, pszPath) — forward to ceshell.dll */
    Thunk("SHGetPathFromIDList", forwardToArm("ceshell.dll", "SHGetPathFromIDList", 2));
    /* SHBrowseForFolder(lpbi) — forward to ceshell.dll */
    Thunk("SHBrowseForFolder", forwardToArm("ceshell.dll", "SHBrowseForFolder", 1));
    /* SHFileOperation(lpFileOp) — forward to ceshell.dll (exported as SHFileOperationW) */
    Thunk("SHFileOperation", forwardToArm("ceshell.dll", "SHFileOperationW", 1));
    Thunk("ExtractIconExW", stub0("ExtractIconExW"));
    Thunk("DragAcceptFiles", [](uint32_t* regs, EmulatedMemory&) -> bool {
        return true; /* void */
    });
    Thunk("SHFreeNameMappings", [](uint32_t* regs, EmulatedMemory&) -> bool {
        return true; /* void */
    });
    /* aygshell re-exports via coredll */
    Thunk("SHHandleWMSettingChange", stub0("SHHandleWMSettingChange"));
    Thunk("SHHandleWMActivate", stub0("SHHandleWMActivate"));
    ThunkOrdinal("SHInitDialog", 1791);
    ThunkOrdinal("SHFullScreen", 1790);
    Thunk("SHCreateMenuBar", stub0("SHCreateMenuBar"));
    ThunkOrdinal("SHSipPreference", 1786);
    Thunk("SHRecognizeGesture", stub0("SHRecognizeGesture"));
    Thunk("SHSendBackToFocusWindow", stub0("SHSendBackToFocusWindow"));
    ThunkOrdinal("SHSetAppKeyWndAssoc", 1784);
    Thunk("SHDoneButton", 1782, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hwnd = (HWND)(intptr_t)(int32_t)regs[0];
        DWORD dwState = regs[1];
        LOG(THUNK, "[THUNK] SHDoneButton(hwnd=0x%p, dwState=%d)\n", hwnd, dwState);
        if (!hwnd) { regs[0] = 0; return true; }
        if (dwState == 1 /*SHDB_SHOW*/ || dwState == 4 /*SHDB_SHOWCANCEL*/) {
            if (captionok_hwnds.insert(hwnd).second) InstallCaptionOk(hwnd);
        } else if (dwState == 2 /*SHDB_HIDE*/) {
            if (captionok_hwnds.erase(hwnd)) RemoveCaptionOk(hwnd);
        }
        regs[0] = 1;
        return true;
    });
    Thunk("SHSipInfo", stub0("SHSipInfo"));
    ThunkOrdinal("SHNotificationAdd", 1806);
    ThunkOrdinal("SHNotificationRemove", 1808);
    ThunkOrdinal("SHNotificationUpdate", 1807);
}
