#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include <cstdio>
#include <algorithm>
#include <commctrl.h>

/* On x64, Windows handles are 32-bit values sign-extended to 64-bit.
   When passing handles from ARM registers to native APIs, we must sign-extend
   (cast through int32_t -> intptr_t) rather than zero-extend (uintptr_t). */

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "imm32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "msimg32.lib")

std::wstring ReadWStringFromEmu(EmulatedMemory& mem, uint32_t addr) {
    if (addr == 0) return L"";
    std::wstring result;
    for (int i = 0; i < 4096; i++) {
        uint16_t ch = mem.Read16(addr + i * 2);
        if (ch == 0) break;
        result += (wchar_t)ch;
    }
    return result;
}

std::string ReadStringFromEmu(EmulatedMemory& mem, uint32_t addr) {
    if (addr == 0) return "";
    std::string result;
    for (int i = 0; i < 4096; i++) {
        uint8_t ch = mem.Read8(addr + i);
        if (ch == 0) break;
        result += (char)ch;
    }
    return result;
}

std::map<uint16_t, std::string> Win32Thunks::ordinal_map;

void Win32Thunks::InitOrdinalMap() {
    if (!ordinal_map.empty()) return;
    /* COREDLL ordinal-to-name mapping from Exports.def */
    ordinal_map[2] = "InitializeCriticalSection";
    ordinal_map[3] = "DeleteCriticalSection";
    ordinal_map[4] = "EnterCriticalSection";
    ordinal_map[5] = "LeaveCriticalSection";
    ordinal_map[6] = "ExitThread";
    ordinal_map[15] = "TlsGetValue";
    ordinal_map[16] = "TlsSetValue";
    ordinal_map[18] = "CompareFileTime";
    ordinal_map[19] = "SystemTimeToFileTime";
    ordinal_map[20] = "FileTimeToSystemTime";
    ordinal_map[21] = "FileTimeToLocalFileTime";
    ordinal_map[23] = "GetLocalTime";
    ordinal_map[24] = "SetLocalTime";
    ordinal_map[25] = "GetSystemTime";
    ordinal_map[27] = "GetTimeZoneInformation";
    ordinal_map[32] = "GetAPIAddress";
    ordinal_map[33] = "LocalAlloc";
    ordinal_map[34] = "LocalReAlloc";
    ordinal_map[35] = "LocalSize";
    ordinal_map[36] = "LocalFree";
    ordinal_map[44] = "HeapCreate";
    ordinal_map[46] = "HeapAlloc";
    ordinal_map[47] = "HeapReAlloc";
    ordinal_map[48] = "HeapSize";
    ordinal_map[49] = "HeapFree";
    ordinal_map[50] = "GetProcessHeap";
    ordinal_map[51] = "HeapValidate";
    ordinal_map[56] = "wsprintfW";
    ordinal_map[57] = "wvsprintfW";
    ordinal_map[58] = "wcscat";
    ordinal_map[59] = "wcschr";
    ordinal_map[60] = "wcscmp";
    ordinal_map[61] = "wcscpy";
    ordinal_map[63] = "wcslen";
    ordinal_map[64] = "wcsncat";
    ordinal_map[65] = "wcsncmp";
    ordinal_map[66] = "wcsncpy";
    ordinal_map[68] = "wcspbrk";
    ordinal_map[69] = "wcsrchr";
    ordinal_map[73] = "wcsstr";
    ordinal_map[74] = "_wcsdup";
    ordinal_map[75] = "wcstombs";
    ordinal_map[76] = "mbstowcs";
    ordinal_map[77] = "wcstok";
    ordinal_map[78] = "_wtol";
    ordinal_map[80] = "Random";
    ordinal_map[87] = "_except_handler4_common";
    ordinal_map[88] = "GlobalMemoryStatus";
    ordinal_map[89] = "SystemParametersInfoW";
    ordinal_map[90] = "CreateDIBSection";
    ordinal_map[91] = "EqualRgn";
    ordinal_map[94] = "LoadAcceleratorsW";
    ordinal_map[95] = "RegisterClassW";
    ordinal_map[96] = "CopyRect";
    ordinal_map[97] = "EqualRect";
    ordinal_map[98] = "InflateRect";
    ordinal_map[99] = "IntersectRect";
    ordinal_map[100] = "IsRectEmpty";
    ordinal_map[101] = "OffsetRect";
    ordinal_map[102] = "PtInRect";
    ordinal_map[103] = "SetRect";
    ordinal_map[104] = "SetRectEmpty";
    ordinal_map[105] = "SubtractRect";
    ordinal_map[106] = "UnionRect";
    ordinal_map[160] = "CreateDirectoryW";
    ordinal_map[162] = "GetTempPathW";
    ordinal_map[163] = "MoveFileW";
    ordinal_map[164] = "CopyFileW";
    ordinal_map[165] = "DeleteFileW";
    ordinal_map[166] = "GetFileAttributesW";
    ordinal_map[167] = "FindFirstFileW";
    ordinal_map[168] = "CreateFileW";
    ordinal_map[170] = "ReadFile";
    ordinal_map[171] = "WriteFile";
    ordinal_map[172] = "GetFileSize";
    ordinal_map[173] = "SetFilePointer";
    ordinal_map[175] = "FlushFileBuffers";
    ordinal_map[176] = "GetFileTime";
    ordinal_map[177] = "SetFileTime";
    ordinal_map[179] = "DeviceIoControl";
    ordinal_map[180] = "FindClose";
    ordinal_map[181] = "FindNextFileW";
    ordinal_map[183] = "DeleteAndRenameFile";
    ordinal_map[184] = "GetDiskFreeSpaceExW";
    ordinal_map[186] = "GetACP";
    ordinal_map[187] = "GetOEMCP";
    ordinal_map[188] = "GetCPInfo";
    ordinal_map[193] = "iswctype";
    ordinal_map[194] = "towlower";
    ordinal_map[195] = "towupper";
    ordinal_map[196] = "MultiByteToWideChar";
    ordinal_map[197] = "WideCharToMultiByte";
    ordinal_map[198] = "CompareStringW";
    ordinal_map[199] = "LCMapStringW";
    ordinal_map[200] = "GetLocaleInfoW";
    ordinal_map[202] = "GetTimeFormatW";
    ordinal_map[203] = "GetDateFormatW";
    ordinal_map[210] = "ConvertDefaultLocale";
    ordinal_map[211] = "GetSystemDefaultLangID";
    ordinal_map[213] = "GetSystemDefaultLCID";
    ordinal_map[215] = "GetUserDefaultLCID";
    ordinal_map[216] = "GetStringTypeW";
    ordinal_map[221] = "CharLowerW";
    ordinal_map[224] = "CharUpperW";
    ordinal_map[226] = "CharNextW";
    ordinal_map[227] = "lstrcmpW";
    ordinal_map[228] = "lstrcmpiW";
    ordinal_map[229] = "_wcsnicmp";
    ordinal_map[230] = "_wcsicmp";
    ordinal_map[234] = "FormatMessageW";
    ordinal_map[246] = "CreateWindowExW";
    ordinal_map[247] = "SetWindowPos";
    ordinal_map[248] = "GetWindowRect";
    ordinal_map[249] = "GetClientRect";
    ordinal_map[250] = "InvalidateRect";
    ordinal_map[251] = "GetWindow";
    ordinal_map[252] = "WindowFromPoint";
    ordinal_map[254] = "ClientToScreen";
    ordinal_map[255] = "ScreenToClient";
    ordinal_map[256] = "SetWindowTextW";
    ordinal_map[257] = "GetWindowTextW";
    ordinal_map[258] = "SetWindowLongW";
    ordinal_map[259] = "GetWindowLongW";
    ordinal_map[260] = "BeginPaint";
    ordinal_map[261] = "EndPaint";
    ordinal_map[262] = "GetDC";
    ordinal_map[263] = "ReleaseDC";
    ordinal_map[264] = "DefWindowProcW";
    ordinal_map[265] = "DestroyWindow";
    ordinal_map[266] = "ShowWindow";
    ordinal_map[267] = "UpdateWindow";
    ordinal_map[268] = "SetParent";
    ordinal_map[269] = "GetParent";
    ordinal_map[270] = "GetWindowDC";
    ordinal_map[271] = "IsWindow";
    ordinal_map[272] = "MoveWindow";
    ordinal_map[274] = "GetUpdateRect";
    ordinal_map[275] = "BringWindowToTop";
    ordinal_map[276] = "GetWindowTextLengthW";
    ordinal_map[278] = "ValidateRect";
    ordinal_map[279] = "SetScrollInfo";
    ordinal_map[280] = "SetScrollPos";
    ordinal_map[281] = "SetScrollRange";
    ordinal_map[282] = "GetScrollInfo";
    ordinal_map[284] = "MapWindowPoints";
    ordinal_map[285] = "CallWindowProcW";
    ordinal_map[286] = "FindWindowW";
    ordinal_map[287] = "EnableWindow";
    ordinal_map[288] = "IsWindowEnabled";
    ordinal_map[289] = "ScrollWindowEx";
    ordinal_map[291] = "EnumWindows";
    ordinal_map[292] = "GetWindowThreadProcessId";
    ordinal_map[295] = "SHGetSpecialFolderPath";
    ordinal_map[342] = "RasDial";
    ordinal_map[377] = "sndPlaySoundW";
    ordinal_map[455] = "RegCloseKey";
    ordinal_map[456] = "RegCreateKeyExW";
    ordinal_map[457] = "RegDeleteKeyW";
    ordinal_map[458] = "RegDeleteValueW";
    ordinal_map[459] = "RegEnumValueW";
    ordinal_map[460] = "RegEnumKeyExW";
    ordinal_map[461] = "RegOpenKeyExW";
    ordinal_map[462] = "RegQueryInfoKeyW";
    ordinal_map[463] = "RegQueryValueExW";
    ordinal_map[464] = "RegSetValueExW";
    ordinal_map[480] = "ShellExecuteEx";
    ordinal_map[481] = "Shell_NotifyIcon";
    ordinal_map[484] = "SHCreateShortcut";
    ordinal_map[487] = "SHLoadDIBitmap";
    ordinal_map[491] = "TerminateThread";
    ordinal_map[492] = "CreateThread";
    ordinal_map[493] = "CreateProcessW";
    ordinal_map[494] = "EventModify";
    ordinal_map[495] = "CreateEventW";
    ordinal_map[496] = "Sleep";
    ordinal_map[497] = "WaitForSingleObject";
    ordinal_map[498] = "WaitForMultipleObjects";
    ordinal_map[508] = "FlushInstructionCache";
    ordinal_map[509] = "OpenProcess";
    ordinal_map[514] = "SetThreadPriority";
    ordinal_map[516] = "GetLastError";
    ordinal_map[517] = "SetLastError";
    ordinal_map[519] = "GetExitCodeProcess";
    ordinal_map[520] = "TlsCall";
    ordinal_map[524] = "VirtualAlloc";
    ordinal_map[525] = "VirtualFree";
    ordinal_map[528] = "LoadLibraryW";
    ordinal_map[529] = "FreeLibrary";
    ordinal_map[530] = "GetProcAddressW";
    ordinal_map[532] = "FindResourceW";
    ordinal_map[533] = "LoadResource";
    ordinal_map[534] = "SizeofResource";
    ordinal_map[535] = "GetTickCount";
    ordinal_map[536] = "GetProcessVersion";
    ordinal_map[537] = "GetModuleFileNameW";
    ordinal_map[541] = "OutputDebugStringW";
    ordinal_map[542] = "GetSystemInfo";
    ordinal_map[543] = "RaiseException";
    ordinal_map[544] = "TerminateProcess";
    ordinal_map[548] = "CreateFileMappingW";
    ordinal_map[549] = "MapViewOfFile";
    ordinal_map[550] = "UnmapViewOfFile";
    ordinal_map[553] = "CloseHandle";
    ordinal_map[555] = "CreateMutexW";
    ordinal_map[556] = "ReleaseMutex";
    ordinal_map[606] = "GetOwnerProcess";
    ordinal_map[658] = "CreateCaret";
    ordinal_map[660] = "HideCaret";
    ordinal_map[661] = "ShowCaret";
    ordinal_map[668] = "OpenClipboard";
    ordinal_map[669] = "CloseClipboard";
    ordinal_map[671] = "SetClipboardData";
    ordinal_map[672] = "GetClipboardData";
    ordinal_map[675] = "EnumClipboardFormats";
    ordinal_map[677] = "EmptyClipboard";
    ordinal_map[678] = "IsClipboardFormatAvailable";
    ordinal_map[682] = "SetCursor";
    ordinal_map[683] = "LoadCursorW";
    ordinal_map[684] = "CheckRadioButton";
    ordinal_map[685] = "SendDlgItemMessageW";
    ordinal_map[686] = "SetDlgItemTextW";
    ordinal_map[687] = "GetDlgItemTextW";
    ordinal_map[688] = "CreateDialogIndirectParamW";
    ordinal_map[689] = "DefDlgProcW";
    ordinal_map[690] = "DialogBoxIndirectParamW";
    ordinal_map[691] = "EndDialog";
    ordinal_map[692] = "GetDlgItem";
    ordinal_map[693] = "GetDlgCtrlID";
    ordinal_map[696] = "GetNextDlgTabItem";
    ordinal_map[698] = "IsDialogMessageW";
    ordinal_map[701] = "GetForegroundWindow";
    ordinal_map[702] = "SetForegroundWindow";
    ordinal_map[703] = "SetActiveWindow";
    ordinal_map[704] = "SetFocus";
    ordinal_map[705] = "GetFocus";
    ordinal_map[706] = "GetActiveWindow";
    ordinal_map[708] = "SetCapture";
    ordinal_map[709] = "ReleaseCapture";
    ordinal_map[717] = "GetVersionExW";
    ordinal_map[722] = "CreateCursor";
    ordinal_map[724] = "DestroyCursor";
    ordinal_map[725] = "DestroyIcon";
    ordinal_map[726] = "DrawIconEx";
    ordinal_map[728] = "LoadIconW";
    ordinal_map[730] = "LoadImageW";
    ordinal_map[731] = "ClipCursor";
    ordinal_map[732] = "GetClipCursor";
    ordinal_map[733] = "GetCursor";
    ordinal_map[734] = "GetCursorPos";
    ordinal_map[736] = "SetCursorPos";
    ordinal_map[737] = "ShowCursor";
    ordinal_map[738] = "ImageList_Add";
    ordinal_map[742] = "ImageList_Create";
    ordinal_map[743] = "ImageList_Destroy";
    ordinal_map[748] = "ImageList_Draw";
    ordinal_map[749] = "ImageList_DrawEx";
    ordinal_map[756] = "ImageList_GetImageCount";
    ordinal_map[755] = "ImageList_GetIconSize";
    ordinal_map[770] = "ImmAssociateContext";
    ordinal_map[783] = "ImmGetContext";
    ordinal_map[803] = "ImmReleaseContext";
    ordinal_map[826] = "GetAsyncKeyState";
    ordinal_map[838] = "TranslateAcceleratorW";
    ordinal_map[842] = "AppendMenuW";
    ordinal_map[844] = "DestroyMenu";
    ordinal_map[845] = "TrackPopupMenuEx";
    ordinal_map[846] = "LoadMenuW";
    ordinal_map[847] = "EnableMenuItem";
    ordinal_map[848] = "CheckMenuItem";
    ordinal_map[849] = "CheckMenuRadioItem";
    ordinal_map[851] = "CreateMenu";
    ordinal_map[852] = "CreatePopupMenu";
    ordinal_map[855] = "GetSubMenu";
    ordinal_map[856] = "DrawMenuBar";
    ordinal_map[857] = "MessageBeep";
    ordinal_map[858] = "MessageBoxW";
    ordinal_map[859] = "DispatchMessageW";
    ordinal_map[860] = "GetKeyState";
    ordinal_map[861] = "GetMessageW";
    ordinal_map[862] = "GetMessagePos";
    ordinal_map[864] = "PeekMessageW";
    ordinal_map[865] = "PostMessageW";
    ordinal_map[866] = "PostQuitMessage";
    ordinal_map[868] = "SendMessageW";
    ordinal_map[869] = "SendNotifyMessageW";
    ordinal_map[870] = "TranslateMessage";
    ordinal_map[871] = "MsgWaitForMultipleObjectsEx";
    ordinal_map[873] = "LoadBitmapW";
    ordinal_map[874] = "LoadStringW";
    ordinal_map[875] = "SetTimer";
    ordinal_map[876] = "KillTimer";
    ordinal_map[878] = "GetClassInfoW";
    ordinal_map[884] = "UnregisterClassW";
    ordinal_map[885] = "GetSystemMetrics";
    ordinal_map[886] = "IsWindowVisible";
    ordinal_map[887] = "AdjustWindowRectEx";
    ordinal_map[888] = "GetDoubleClickTime";
    ordinal_map[889] = "GetSysColor";
    ordinal_map[891] = "RegisterWindowMessageW";
    ordinal_map[895] = "CreateFontIndirectW";
    ordinal_map[896] = "ExtTextOutW";
    ordinal_map[897] = "GetTextExtentExPointW";
    ordinal_map[898] = "GetTextMetricsW";
    ordinal_map[901] = "CreateBitmap";
    ordinal_map[902] = "CreateCompatibleBitmap";
    ordinal_map[903] = "BitBlt";
    ordinal_map[905] = "StretchBlt";
    ordinal_map[906] = "TransparentBlt";
    ordinal_map[907] = "RestoreDC";
    ordinal_map[908] = "SaveDC";
    ordinal_map[909] = "CreateDCW";
    ordinal_map[910] = "CreateCompatibleDC";
    ordinal_map[911] = "DeleteDC";
    ordinal_map[912] = "DeleteObject";
    ordinal_map[916] = "GetDeviceCaps";
    ordinal_map[918] = "GetObjectW";
    ordinal_map[919] = "GetStockObject";
    ordinal_map[920] = "SetStretchBltMode";
    ordinal_map[921] = "SelectObject";
    ordinal_map[922] = "SetBkColor";
    ordinal_map[923] = "SetBkMode";
    ordinal_map[924] = "SetTextColor";
    ordinal_map[926] = "CreatePen";
    ordinal_map[931] = "CreateSolidBrush";
    ordinal_map[933] = "DrawFocusRect";
    ordinal_map[935] = "FillRect";
    ordinal_map[936] = "GetPixel";
    ordinal_map[937] = "GetSysColorBrush";
    ordinal_map[938] = "PatBlt";
    ordinal_map[939] = "Polygon";
    ordinal_map[940] = "Polyline";
    ordinal_map[941] = "Rectangle";
    ordinal_map[944] = "SetPixel";
    ordinal_map[945] = "DrawTextW";
    ordinal_map[952] = "GetNearestColor";
    ordinal_map[953] = "RealizePalette";
    ordinal_map[954] = "SelectPalette";
    ordinal_map[968] = "CombineRgn";
    ordinal_map[969] = "CreateRectRgnIndirect";
    ordinal_map[971] = "GetClipBox";
    ordinal_map[975] = "IntersectClipRect";
    ordinal_map[979] = "SelectClipRgn";
    ordinal_map[980] = "CreateRectRgn";
    ordinal_map[983] = "SetViewportOrgEx";
    ordinal_map[1013] = "floor";
    ordinal_map[1018] = "free";
    ordinal_map[1041] = "malloc";
    ordinal_map[1043] = "memcmp";
    ordinal_map[1044] = "memcpy";
    ordinal_map[1046] = "memmove";
    ordinal_map[1047] = "memset";
    ordinal_map[1051] = "pow";
    ordinal_map[1052] = "qsort";
    ordinal_map[1053] = "rand";
    ordinal_map[1054] = "realloc";
    ordinal_map[1082] = "wcstol";
    ordinal_map[1092] = "_purecall";
    ordinal_map[1094] = "delete";
    ordinal_map[1095] = "new";
    ordinal_map[1096] = "_snwprintf";
    ordinal_map[1097] = "swprintf";
    ordinal_map[1098] = "swscanf";
    ordinal_map[1177] = "GetModuleHandleW";
    ordinal_map[1231] = "GetCommandLineW";
    ordinal_map[1232] = "DisableThreadLibraryCalls";
    ordinal_map[1346] = "calloc";
    ordinal_map[1397] = "GetDesktopWindow";
    ordinal_map[1519] = "GlobalAddAtomW";
    ordinal_map[1556] = "terminate";
    ordinal_map[1601] = "CeGenRandom";
    ordinal_map[1651] = "MoveToEx";
    ordinal_map[1652] = "LineTo";
    ordinal_map[1654] = "SetTextAlign";
    ordinal_map[1655] = "GetTextAlign";
    ordinal_map[1667] = "StretchDIBits";
    ordinal_map[1763] = "GradientFill";
    ordinal_map[1770] = "InvertRect";
    ordinal_map[1875] = "__security_gen_cookie";
    ordinal_map[1877] = "MulDiv";
    ordinal_map[1890] = "SetLayout";
    ordinal_map[1891] = "GetLayout";
    ordinal_map[2000] = "_setjmp3";
    ordinal_map[2005] = "__PlatformSpecific2005"; /* Platform-specific, silent no-op */
    ordinal_map[2008] = "__PlatformSpecific2008"; /* Platform-specific, silent no-op */
    ordinal_map[2528] = "__GetUserKData";
    ordinal_map[2562] = "WaitForAPIReady";
    ordinal_map[2696] = "__security_gen_cookie2";
    ordinal_map[2924] = "CloseGestureInfoHandle";
    ordinal_map[2925] = "GetGestureInfo";
    ordinal_map[2928] = "RegisterDefaultGestureHandler";
}

std::string Win32Thunks::ResolveOrdinal(uint16_t ordinal) {
    auto it = ordinal_map.find(ordinal);
    if (it != ordinal_map.end()) return it->second;
    char buf[32];
    sprintf(buf, "ordinal_%d", ordinal);
    return buf;
}

std::map<HWND, uint32_t> Win32Thunks::hwnd_wndproc_map;
std::map<UINT_PTR, uint32_t> Win32Thunks::arm_timer_callbacks;
std::map<HWND, uint32_t> Win32Thunks::hwnd_dlgproc_map;
INT_PTR Win32Thunks::modal_dlg_result = 0;
bool Win32Thunks::modal_dlg_ended = false;
Win32Thunks* Win32Thunks::s_instance = nullptr;

INT_PTR CALLBACK Win32Thunks::EmuDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (!s_instance || !s_instance->callback_executor) {
        return FALSE;
    }

    /* Messages with native 64-bit pointers that can't be safely truncated
       to 32 bits for ARM code - let the default dialog proc handle them. */
    switch (msg) {
    case WM_GETMINMAXINFO:
    case WM_NCCALCSIZE:
    case WM_WINDOWPOSCHANGING:
    case WM_WINDOWPOSCHANGED:
    case WM_STYLECHANGING:
    case WM_STYLECHANGED:
    case WM_SETTEXT:
    case WM_GETTEXT:
    case WM_SETICON:
    case WM_NOTIFY:
    case WM_NCHITTEST:
    case WM_NCPAINT:
        return FALSE; /* Not handled - let default dialog proc deal with it */
    }

    auto it = hwnd_dlgproc_map.find(hwnd);
    if (it == hwnd_dlgproc_map.end()) {
        if (msg == WM_INITDIALOG) {
            return FALSE;
        }
        return FALSE;
    }

    uint32_t arm_dlgproc = it->second;

    /* Marshal owner-draw structs from native 64-bit layout to 32-bit ARM layout */
    static uint32_t odi_emu_addr = 0x3F001000;
    EmulatedMemory& emem = s_instance->mem;
    if (!emem.IsValid(odi_emu_addr)) emem.Alloc(odi_emu_addr, 0x1000);

    uint32_t emu_lParam = (uint32_t)lParam;

    if (msg == WM_DRAWITEM && lParam) {
        DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lParam;
        /* 32-bit DRAWITEMSTRUCT layout (48 bytes):
           +0  CtlType, +4 CtlID, +8 itemID, +12 itemAction, +16 itemState,
           +20 hwndItem(32), +24 hDC(32), +28 rcItem(16), +44 itemData(32) */
        emem.Write32(odi_emu_addr + 0,  dis->CtlType);
        emem.Write32(odi_emu_addr + 4,  dis->CtlID);
        emem.Write32(odi_emu_addr + 8,  dis->itemID);
        emem.Write32(odi_emu_addr + 12, dis->itemAction);
        emem.Write32(odi_emu_addr + 16, dis->itemState);
        emem.Write32(odi_emu_addr + 20, (uint32_t)(uintptr_t)dis->hwndItem);
        emem.Write32(odi_emu_addr + 24, (uint32_t)(uintptr_t)dis->hDC);
        emem.Write32(odi_emu_addr + 28, dis->rcItem.left);
        emem.Write32(odi_emu_addr + 32, dis->rcItem.top);
        emem.Write32(odi_emu_addr + 36, dis->rcItem.right);
        emem.Write32(odi_emu_addr + 40, dis->rcItem.bottom);
        emem.Write32(odi_emu_addr + 44, (uint32_t)dis->itemData);
        emu_lParam = odi_emu_addr;
    } else if (msg == WM_MEASUREITEM && lParam) {
        MEASUREITEMSTRUCT* mis = (MEASUREITEMSTRUCT*)lParam;
        /* 32-bit MEASUREITEMSTRUCT layout (24 bytes):
           +0 CtlType, +4 CtlID, +8 itemID, +12 itemWidth, +16 itemHeight, +20 itemData(32) */
        emem.Write32(odi_emu_addr + 0,  mis->CtlType);
        emem.Write32(odi_emu_addr + 4,  mis->CtlID);
        emem.Write32(odi_emu_addr + 8,  mis->itemID);
        emem.Write32(odi_emu_addr + 12, mis->itemWidth);
        emem.Write32(odi_emu_addr + 16, mis->itemHeight);
        emem.Write32(odi_emu_addr + 20, (uint32_t)mis->itemData);
        emu_lParam = odi_emu_addr;
    }

    uint32_t args[4] = {
        (uint32_t)(uintptr_t)hwnd,
        (uint32_t)msg,
        (uint32_t)wParam,
        emu_lParam
    };

    uint32_t result = s_instance->callback_executor(arm_dlgproc, args, 4);

    /* Copy back results from WM_MEASUREITEM */
    if (msg == WM_MEASUREITEM && lParam) {
        MEASUREITEMSTRUCT* mis = (MEASUREITEMSTRUCT*)lParam;
        mis->itemWidth = emem.Read32(odi_emu_addr + 12);
        mis->itemHeight = emem.Read32(odi_emu_addr + 16);
    }

    return (INT_PTR)result;
}

LRESULT CALLBACK Win32Thunks::EmuWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (!s_instance || !s_instance->callback_executor) {
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    auto it = hwnd_wndproc_map.find(hwnd);
    if (it == hwnd_wndproc_map.end()) {
        /* During CreateWindow, HWND is not yet in the map.
           Look up the ARM WndProc from the window class name and auto-register. */
        wchar_t cls_name[256] = {};
        GetClassNameW(hwnd, cls_name, 256);
        auto cls_it = s_instance->arm_wndprocs.find(cls_name);
        if (cls_it != s_instance->arm_wndprocs.end()) {
            hwnd_wndproc_map[hwnd] = cls_it->second;
            it = hwnd_wndproc_map.find(hwnd);
        } else {
            return DefWindowProcW(hwnd, msg, wParam, lParam);
        }
    }

    /* Messages with native pointer lParams need marshaling.
       For messages we can't marshal, use DefWindowProcW. */
    LPARAM native_lParam = lParam; /* Save for writeback after ARM callback */
    switch (msg) {
    /* Messages with native 64-bit pointers in wParam/lParam that would be
       corrupted if truncated to 32-bit for the ARM WndProc. Route these
       directly to DefWindowProcW to avoid pointer truncation. */
    case WM_GETMINMAXINFO:      /* lParam = MINMAXINFO* */
    case WM_NCCALCSIZE:         /* lParam = NCCALCSIZE_PARAMS* */
    case WM_WINDOWPOSCHANGING:  /* lParam = WINDOWPOS* */
    case WM_WINDOWPOSCHANGED:   /* lParam = WINDOWPOS* */
    case WM_STYLECHANGING:      /* lParam = STYLESTRUCT* */
    case WM_STYLECHANGED:       /* lParam = STYLESTRUCT* */
    case WM_NCDESTROY:
    case WM_SETTEXT:            /* lParam = LPCWSTR (native pointer) */
    case WM_GETTEXT:            /* lParam = LPWSTR (native buffer) */
    case WM_GETTEXTLENGTH:
    case WM_SETICON:            /* lParam = HICON (64-bit on x64) */
    case WM_GETICON:
    case WM_COPYDATA:           /* lParam = COPYDATASTRUCT* */
    case WM_NOTIFY:             /* lParam = NMHDR* */
    case WM_DELETEITEM:         /* lParam = DELETEITEMSTRUCT* */
    case WM_COMPAREITEM:        /* lParam = COMPAREITEMSTRUCT* */
    case WM_DISPLAYCHANGE:
    case WM_DEVICECHANGE:
    case WM_POWERBROADCAST:
    case WM_INPUT:              /* lParam = HRAWINPUT */
    case WM_NCHITTEST:
    case WM_NCPAINT:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    case WM_CREATE:
    case WM_NCCREATE: {
        /* Marshal CREATESTRUCT into emulated memory (32-bit layout) */
        CREATESTRUCTW* cs = (CREATESTRUCTW*)lParam;
        static uint32_t cs_emu_addr = 0x3F000000;
        EmulatedMemory& emem = s_instance->mem;
        if (!emem.IsValid(cs_emu_addr)) emem.Alloc(cs_emu_addr, 0x1000);
        emem.Write32(cs_emu_addr + 0,  0);
        emem.Write32(cs_emu_addr + 4,  s_instance->emu_hinstance);
        emem.Write32(cs_emu_addr + 8,  0);
        emem.Write32(cs_emu_addr + 12, (uint32_t)(uintptr_t)cs->hwndParent);
        emem.Write32(cs_emu_addr + 16, cs->cy);
        emem.Write32(cs_emu_addr + 20, cs->cx);
        emem.Write32(cs_emu_addr + 24, cs->y);
        emem.Write32(cs_emu_addr + 28, cs->x);
        emem.Write32(cs_emu_addr + 32, cs->style);
        emem.Write32(cs_emu_addr + 36, 0);
        emem.Write32(cs_emu_addr + 40, 0);
        emem.Write32(cs_emu_addr + 44, cs->dwExStyle);
        lParam = (LPARAM)cs_emu_addr;
        break;
    }
    case WM_DRAWITEM: {
        /* Marshal DRAWITEMSTRUCT into emulated memory (64-bit -> 32-bit) */
        static uint32_t wdi_emu_addr = 0x3F002000;
        EmulatedMemory& emem = s_instance->mem;
        if (!emem.IsValid(wdi_emu_addr)) emem.Alloc(wdi_emu_addr, 0x1000);
        DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lParam;
        emem.Write32(wdi_emu_addr + 0,  dis->CtlType);
        emem.Write32(wdi_emu_addr + 4,  dis->CtlID);
        emem.Write32(wdi_emu_addr + 8,  dis->itemID);
        emem.Write32(wdi_emu_addr + 12, dis->itemAction);
        emem.Write32(wdi_emu_addr + 16, dis->itemState);
        emem.Write32(wdi_emu_addr + 20, (uint32_t)(uintptr_t)dis->hwndItem);
        emem.Write32(wdi_emu_addr + 24, (uint32_t)(uintptr_t)dis->hDC);
        emem.Write32(wdi_emu_addr + 28, dis->rcItem.left);
        emem.Write32(wdi_emu_addr + 32, dis->rcItem.top);
        emem.Write32(wdi_emu_addr + 36, dis->rcItem.right);
        emem.Write32(wdi_emu_addr + 40, dis->rcItem.bottom);
        emem.Write32(wdi_emu_addr + 44, (uint32_t)dis->itemData);
        lParam = (LPARAM)wdi_emu_addr;
        break;
    }
    case WM_MEASUREITEM: {
        /* Marshal MEASUREITEMSTRUCT into emulated memory (64-bit -> 32-bit) */
        static uint32_t wmi_emu_addr = 0x3F002100;
        EmulatedMemory& emem = s_instance->mem;
        if (!emem.IsValid(wmi_emu_addr)) emem.Alloc(wmi_emu_addr, 0x1000);
        MEASUREITEMSTRUCT* mis = (MEASUREITEMSTRUCT*)lParam;
        emem.Write32(wmi_emu_addr + 0,  mis->CtlType);
        emem.Write32(wmi_emu_addr + 4,  mis->CtlID);
        emem.Write32(wmi_emu_addr + 8,  mis->itemID);
        emem.Write32(wmi_emu_addr + 12, mis->itemWidth);
        emem.Write32(wmi_emu_addr + 16, mis->itemHeight);
        emem.Write32(wmi_emu_addr + 20, (uint32_t)mis->itemData);
        lParam = (LPARAM)wmi_emu_addr;
        break;
    }
    }

    uint32_t arm_wndproc = it->second;
    uint32_t args[4] = {
        (uint32_t)(uintptr_t)hwnd,
        (uint32_t)msg,
        (uint32_t)wParam,
        (uint32_t)lParam
    };

    uint32_t result = s_instance->callback_executor(arm_wndproc, args, 4);

    /* Copy back results from WM_MEASUREITEM */
    if (msg == WM_MEASUREITEM && native_lParam) {
        static uint32_t wmi_emu_addr = 0x3F002100;
        MEASUREITEMSTRUCT* mis = (MEASUREITEMSTRUCT*)native_lParam;
        EmulatedMemory& emem = s_instance->mem;
        mis->itemWidth = emem.Read32(wmi_emu_addr + 12);
        mis->itemHeight = emem.Read32(wmi_emu_addr + 16);
    }

    return (LRESULT)result;
}

Win32Thunks::Win32Thunks(EmulatedMemory& mem)
    : mem(mem), next_thunk_addr(THUNK_BASE), emu_hinstance(0) {
    InitOrdinalMap();
    s_instance = this;
    /* Allocate a memory region for thunk return stubs */
    mem.Alloc(THUNK_BASE, 0x100000);
}

uint32_t Win32Thunks::AllocThunk(const std::string& dll, const std::string& func,
                                  uint16_t ordinal, bool by_ordinal) {
    uint32_t addr = next_thunk_addr;
    next_thunk_addr += THUNK_STRIDE;

    ThunkEntry entry;
    entry.dll_name = dll;
    entry.func_name = func;
    entry.ordinal = ordinal;
    entry.by_ordinal = by_ordinal;
    entry.thunk_addr = addr;

    thunks[addr] = entry;

    /* Write a recognizable pattern at the thunk address:
       We write a BX LR instruction (0xE12FFF1E in ARM) so if the
       CPU somehow reaches it, it returns. But normally the thunk
       handler intercepts before execution. */
    mem.Write32(addr, 0xE12FFF1E);

    return addr;
}

void Win32Thunks::InstallThunks(PEInfo& info) {
    for (auto& imp : info.imports) {

        uint32_t thunk_addr = AllocThunk(imp.dll_name, imp.func_name, imp.ordinal, imp.by_ordinal);

        /* Write the thunk address into the IAT */
        mem.Write32(imp.iat_addr, thunk_addr);

        if (imp.by_ordinal) {
            printf("[THUNK] Installed thunk for %s!@%d at 0x%08X -> IAT 0x%08X\n",
                   imp.dll_name.c_str(), imp.ordinal, thunk_addr, imp.iat_addr);
        } else {
            printf("[THUNK] Installed thunk for %s!%s at 0x%08X -> IAT 0x%08X\n",
                   imp.dll_name.c_str(), imp.func_name.c_str(), thunk_addr, imp.iat_addr);
        }
    }
}

uint32_t Win32Thunks::ReadStackArg(uint32_t* regs, EmulatedMemory& mem, int index) {
    /* ARM calling convention: R0-R3 for first 4 args, then stack.
       index 0 = first stack arg (5th overall arg) */
    uint32_t sp = regs[13];
    return mem.Read32(sp + index * 4);
}

uint32_t Win32Thunks::FindResourceInPE(uint32_t module_base, uint32_t rsrc_rva, uint32_t rsrc_size,
                                       uint32_t type_id, uint32_t name_id,
                                       uint32_t& out_data_rva, uint32_t& out_data_size) {
    if (rsrc_rva == 0 || rsrc_size == 0) return 0;

    uint32_t rsrc_base = module_base + rsrc_rva;

    /* Level 1: Type directory */
    uint16_t num_named = mem.Read16(rsrc_base + 12);
    uint16_t num_id = mem.Read16(rsrc_base + 14);
    uint32_t entry_addr = rsrc_base + 16 + num_named * 8; /* Skip named entries */

    uint32_t type_offset = 0;
    for (uint16_t i = 0; i < num_id; i++) {
        uint32_t id = mem.Read32(entry_addr + i * 8);
        uint32_t off = mem.Read32(entry_addr + i * 8 + 4);
        if (id == type_id && (off & 0x80000000)) {
            type_offset = off & 0x7FFFFFFF;
            break;
        }
    }
    if (type_offset == 0) return 0;

    /* Level 2: Name/ID directory */
    uint32_t name_dir = rsrc_base + type_offset;
    num_named = mem.Read16(name_dir + 12);
    num_id = mem.Read16(name_dir + 14);
    entry_addr = name_dir + 16 + num_named * 8;

    uint32_t name_offset = 0;
    for (uint16_t i = 0; i < num_id; i++) {
        uint32_t id = mem.Read32(entry_addr + i * 8);
        uint32_t off = mem.Read32(entry_addr + i * 8 + 4);
        if (id == name_id) {
            if (off & 0x80000000) {
                name_offset = off & 0x7FFFFFFF;
            } else {
                /* Direct data entry */
                uint32_t data_entry = rsrc_base + off;
                out_data_rva = mem.Read32(data_entry);
                out_data_size = mem.Read32(data_entry + 4);
                return 1;
            }
            break;
        }
    }
    if (name_offset == 0) return 0;

    /* Level 3: Language directory - just take the first entry */
    uint32_t lang_dir = rsrc_base + name_offset;
    num_named = mem.Read16(lang_dir + 12);
    num_id = mem.Read16(lang_dir + 14);
    uint32_t total = num_named + num_id;
    if (total == 0) return 0;

    entry_addr = lang_dir + 16;
    uint32_t off = mem.Read32(entry_addr + 4);
    if (off & 0x80000000) return 0; /* Should be a leaf */

    uint32_t data_entry = rsrc_base + off;
    out_data_rva = mem.Read32(data_entry);
    out_data_size = mem.Read32(data_entry + 4);
    return 1;
}

HMODULE Win32Thunks::GetNativeModuleForResources(uint32_t emu_handle) {
    /* Check loaded ARM DLLs */
    for (auto& pair : loaded_dlls) {
        if (pair.second.base_addr == emu_handle) {
            if (!pair.second.native_rsrc_handle) {
                pair.second.native_rsrc_handle = LoadLibraryExA(
                    pair.second.path.c_str(), NULL,
                    LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
            }
            return pair.second.native_rsrc_handle;
        }
    }
    /* Check main exe */
    if (emu_handle == emu_hinstance) {
        static HMODULE exe_rsrc = NULL;
        if (!exe_rsrc) {
            std::string narrow_exe;
            for (auto c : exe_path) narrow_exe += (char)c;
            exe_rsrc = LoadLibraryExA(narrow_exe.c_str(), NULL,
                LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
        }
        return exe_rsrc;
    }
    return NULL;
}

bool Win32Thunks::HandleThunk(uint32_t addr, uint32_t* regs, EmulatedMemory& mem) {
    /* Check if address is in thunk range */
    auto it = thunks.find(addr);
    if (it == thunks.end()) {
        /* Also check addr+1 for Thumb calls */
        it = thunks.find(addr & ~1u);
        if (it == thunks.end()) {
            /* Handle WinCE trap-based API calls (0xF000xxxx range).
               WinCE apps call some APIs via trap addresses descending from 0xF0010000.
               API index = (0xF0010000 - addr) / 4, which maps to COREDLL ordinals. */
            if (addr >= WINCE_TRAP_BASE && addr < WINCE_TRAP_TOP) {
                uint32_t api_index = (WINCE_TRAP_TOP - addr) / 4;
                auto name_it = ordinal_map.find((uint16_t)api_index);
                std::string func_name = (name_it != ordinal_map.end()) ? name_it->second : "";
                if (!func_name.empty()) {
                    printf("[THUNK] WinCE trap 0x%08X -> API %u (%s)\n", addr, api_index, func_name.c_str());
                } else {
                    printf("[THUNK] WinCE trap 0x%08X -> API %u (unknown)\n", addr, api_index);
                }
                /* Create a temporary thunk entry and execute it */
                ThunkEntry trap_entry;
                trap_entry.dll_name = "COREDLL.dll";
                trap_entry.func_name = func_name;
                trap_entry.ordinal = (uint16_t)api_index;
                trap_entry.by_ordinal = true;
                trap_entry.thunk_addr = addr;
                bool result = ExecuteThunk(trap_entry, regs, mem);
                if (result) {
                    uint32_t lr = regs[14];
                    regs[15] = (lr & 1) ? (lr & ~1u) : (lr & ~3u);
                }
                return result;
            }

            /* Detect branches into thunk memory region at unregistered addresses */
            if (addr >= THUNK_BASE && addr < THUNK_BASE + 0x100000) {
                printf("[EMU] ERROR: Branch to unregistered thunk address 0x%08X (LR=0x%08X)\n",
                       addr, regs[14]);
                regs[0] = 0;
                uint32_t lr = regs[14];
                regs[15] = (lr & 1) ? (lr & ~1u) : (lr & ~3u);
                return true;
            }
            return false;
        }
    }

    bool result = ExecuteThunk(it->second, regs, mem);
    if (result) {
        /* Return to caller: set PC = LR */
        uint32_t lr = regs[14];
        if (lr & 1) {
            /* Return to Thumb mode */
            regs[15] = lr & ~1u;
            /* Keep Thumb flag - handled by caller */
        } else {
            regs[15] = lr & ~3u;
        }
    }
    return result;
}

bool Win32Thunks::ExecuteThunk(const ThunkEntry& entry, uint32_t* regs, EmulatedMemory& mem) {
    std::string func = entry.func_name;
    if (func.empty() && entry.by_ordinal) {
        func = ResolveOrdinal(entry.ordinal);
        if (!func.empty()) {
            printf("[THUNK] Resolved ordinal %d -> %s\n", entry.ordinal, func.c_str());
        }
    }

    /* Module/process management thunks (kept in core) */
    if (func == "GetModuleHandleW") return Thunk_GetModuleHandleW(regs, mem);
    if (func == "GetModuleFileNameW") return Thunk_GetModuleFileNameW(regs, mem);
    if (func == "LoadLibraryW") return Thunk_LoadLibraryW(regs, mem);
    if (func == "GetProcAddressW" || func == "GetProcAddressA" || func == "GetProcAddress")
        return Thunk_GetProcAddressW(regs, mem);
    if (func == "GetCommandLineW") return Thunk_GetCommandLineW(regs, mem);

    /* CacheSync / FlushInstructionCache - used by UPX after decompression */
    if (func == "CacheSync" || func == "CacheRangeFlush") {
        regs[0] = 1;
        return true;
    }

    /* Process/thread lifecycle */
    if (func == "ExitProcess" || func == "TerminateProcess")
        return Thunk_ExitProcess(regs, mem);
    if (func == "ExitThread") return Thunk_ExitThread(regs, mem);

    /* Dispatch to category handlers */
    if (ExecuteMemoryThunk(func, regs, mem)) return true;
    if (ExecuteStringThunk(func, regs, mem)) return true;
    if (ExecuteGdiThunk(func, regs, mem)) return true;
    if (ExecuteWindowThunk(func, regs, mem)) return true;
    if (ExecuteSystemThunk(func, regs, mem)) return true;

    /* CEShell.DLL stubs - return proper error codes so apps don't
       dereference NULL COM pointers when shell APIs are unavailable */
    if (entry.dll_name == "CEShell.DLL" || entry.dll_name == "ceshell.dll") {
        if (func == "SHGetSpecialFolderLocation" || func == "SHGetMalloc") {
            /* HRESULT-returning functions: return E_NOTIMPL */
            regs[0] = 0x80004001; /* E_NOTIMPL */
            printf("[THUNK] %s -> E_NOTIMPL (stub)\n", func.c_str());
            return true;
        }
        if (func == "SHGetPathFromIDList" || func == "SHGetShortcutTarget" ||
            func == "SHLoadDIBitmap") {
            /* BOOL/pointer-returning functions: return 0 (FALSE/NULL) */
            regs[0] = 0;
            printf("[THUNK] %s -> 0 (stub)\n", func.c_str());
            return true;
        }
    }

    /* commctrl.dll stubs */
    if (entry.dll_name == "commctrl.dll" || entry.dll_name == "COMMCTRL.DLL") {
        /* InitCommonControlsEx (ordinal 2), InitCommonControls (ordinal 3), etc. */
        regs[0] = 1; /* TRUE - pretend success */
        printf("[THUNK] commctrl.dll!%s (ordinal %d) -> 1 (stub)\n",
               func.empty() ? "(unknown)" : func.c_str(), entry.ordinal);
        return true;
    }

    /* Platform-specific ordinals - silent no-ops */
    if (func == "__PlatformSpecific2005" || func == "__PlatformSpecific2008") {
        regs[0] = 0;
        return true;
    }

    /* If we get here, the function is not handled */
    if (!func.empty()) {
        printf("[THUNK] UNHANDLED: %s!%s (ordinal=%d) - returning 0\n",
               entry.dll_name.c_str(), func.c_str(), entry.ordinal);
    } else if (entry.by_ordinal) {
        printf("[THUNK] UNHANDLED: %s!@%d (no name mapping) - returning 0\n",
               entry.dll_name.c_str(), entry.ordinal);
    } else {
        printf("[THUNK] UNHANDLED: %s!%s - returning 0\n",
               entry.dll_name.c_str(), entry.func_name.c_str());
    }
    regs[0] = 0;
    return true;
}

/* Individual thunk implementations for module/process management */

bool Win32Thunks::Thunk_GetModuleHandleW(uint32_t* regs, EmulatedMemory& mem) {
    uint32_t name_addr = regs[0];
    if (name_addr == 0) {
        regs[0] = emu_hinstance;
        printf("[THUNK] GetModuleHandleW(NULL) -> 0x%08X\n", regs[0]);
    } else {
        std::wstring name = ReadWStringFromEmu(mem, name_addr);
        printf("[THUNK] GetModuleHandleW('%ls')\n", name.c_str());
        /* For coredll.dll, return a fake handle */
        std::wstring lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
        if (lower.find(L"coredll") != std::wstring::npos) {
            regs[0] = 0xCE000000;
        } else {
            regs[0] = emu_hinstance;
        }
    }
    return true;
}

bool Win32Thunks::Thunk_GetModuleFileNameW(uint32_t* regs, EmulatedMemory& mem) {
    uint32_t buf_addr = regs[1];
    uint32_t buf_size = regs[2];
    for (uint32_t i = 0; i < exe_path.size() && i < buf_size; i++) {
        mem.Write16(buf_addr + i * 2, exe_path[i]);
    }
    uint32_t null_off = std::min((uint32_t)exe_path.size(), buf_size - 1);
    mem.Write16(buf_addr + null_off * 2, 0);
    regs[0] = (uint32_t)exe_path.size();
    return true;
}

bool Win32Thunks::Thunk_LoadLibraryW(uint32_t* regs, EmulatedMemory& mem) {
    std::wstring name = ReadWStringFromEmu(mem, regs[0]);
    printf("[THUNK] LoadLibraryW('%ls')\n", name.c_str());

    std::wstring lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    if (lower.find(L"coredll") != std::wstring::npos) {
        regs[0] = 0xCE000000;
        return true;
    }

    /* Check if already loaded */
    auto it = loaded_dlls.find(lower);
    if (it != loaded_dlls.end()) {
        regs[0] = it->second.base_addr;
        printf("[THUNK]   Already loaded at 0x%08X\n", regs[0]);
        return true;
    }

    /* Try to load as ARM DLL from exe directory */
    std::string narrow_name;
    for (auto c : name) narrow_name += (char)c;

    /* Build path: try exe_dir first */
    std::string dll_path = exe_dir + narrow_name;
    FILE* f = fopen(dll_path.c_str(), "rb");
    if (!f) {
        /* Try just the name */
        dll_path = narrow_name;
        f = fopen(dll_path.c_str(), "rb");
    }
    if (!f) {
        printf("[THUNK]   DLL not found: %s\n", narrow_name.c_str());
        regs[0] = 0;
        return true;
    }
    fclose(f);

    /* Load as ARM PE */
    PEInfo dll_info = {};
    uint32_t entry = PELoader::LoadDll(dll_path.c_str(), mem, dll_info);
    if (entry == 0 && dll_info.image_base == 0) {
        printf("[THUNK]   Failed to load ARM DLL: %s\n", dll_path.c_str());
        regs[0] = 0;
        return true;
    }

    LoadedDll loaded;
    loaded.path = dll_path;
    loaded.base_addr = dll_info.image_base;
    loaded.pe_info = dll_info;
    loaded.native_rsrc_handle = NULL;
    loaded_dlls[lower] = loaded;

    regs[0] = dll_info.image_base;
    printf("[THUNK]   Loaded ARM DLL at 0x%08X\n", regs[0]);
    return true;
}

bool Win32Thunks::Thunk_GetProcAddressW(uint32_t* regs, EmulatedMemory& mem) {
    uint32_t hmod = regs[0];
    /* Read function name - could be ANSI string (GetProcAddressA) or ordinal */
    std::string func_name;

    /* Check if it's an ordinal (HIWORD == 0) */
    if ((regs[1] & 0xFFFF0000) == 0 && regs[1] != 0) {
        /* Ordinal import */
        uint16_t ordinal = (uint16_t)regs[1];
        std::string resolved = ResolveOrdinal(ordinal);
        printf("[THUNK] GetProcAddress(0x%08X, ordinal %d -> %s)\n", hmod, ordinal,
               resolved.empty() ? "UNKNOWN" : resolved.c_str());
        /* Create a thunk for this ordinal with resolved name */
        uint32_t thunk_addr = AllocThunk("coredll.dll", resolved, ordinal, resolved.empty());
        regs[0] = thunk_addr;
        return true;
    }

    func_name = ReadStringFromEmu(mem, regs[1]);
    printf("[THUNK] GetProcAddress(0x%08X, '%s')\n", hmod, func_name.c_str());

    if (hmod == 0xCE000000 || func_name.size() > 0) {
        /* Coredll function - allocate a thunk for it */
        uint32_t thunk_addr = AllocThunk("coredll.dll", func_name, 0, false);
        regs[0] = thunk_addr;
        printf("[THUNK]   -> thunk at 0x%08X\n", thunk_addr);
    } else {
        regs[0] = 0;
    }
    return true;
}

bool Win32Thunks::Thunk_GetCommandLineW(uint32_t* regs, EmulatedMemory& mem) {
    /* Allocate a buffer in emulated memory for the command line */
    static uint32_t cmdline_addr = 0;
    if (cmdline_addr == 0) {
        cmdline_addr = 0x50000000;
        mem.Alloc(cmdline_addr, 0x1000);
        LPCWSTR cmdline = GetCommandLineW();
        for (int i = 0; cmdline[i]; i++) {
            mem.Write16(cmdline_addr + i * 2, cmdline[i]);
        }
    }
    regs[0] = cmdline_addr;
    return true;
}

bool Win32Thunks::Thunk_ExitProcess(uint32_t* regs, EmulatedMemory& mem) {
    printf("[THUNK] ExitProcess(%d)\n", regs[0]);
    ExitProcess(regs[0]);
    return true;
}

bool Win32Thunks::Thunk_ExitThread(uint32_t* regs, EmulatedMemory& mem) {
    printf("[THUNK] ExitThread(%d)\n", regs[0]);
    ExitThread(regs[0]);
    return true;
}
