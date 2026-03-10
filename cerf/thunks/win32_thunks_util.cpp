#include "win32_thunks.h"
#include <algorithm>
#include <cstring>

/* Thunked DLL registry — single source of truth for all system DLLs we emulate. */
const ThunkedDllInfo thunked_dlls[] = {
    { "coredll",   0xCE000000 },
};
const size_t thunked_dlls_count = sizeof(thunked_dlls) / sizeof(thunked_dlls[0]);

/* Look up a thunked DLL by name (narrow, case-insensitive, substring match) */
const ThunkedDllInfo* FindThunkedDll(const std::string& dll_name) {
    std::string lower = dll_name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    for (size_t i = 0; i < thunked_dlls_count; ++i)
        if (lower.find(thunked_dlls[i].name) != std::string::npos) return &thunked_dlls[i];
    return nullptr;
}

/* Wide string version for LoadLibraryW / GetModuleHandleW */
const ThunkedDllInfo* FindThunkedDllW(const std::wstring& dll_name) {
    std::wstring lower = dll_name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    for (size_t i = 0; i < thunked_dlls_count; ++i) {
        std::wstring wide_name(thunked_dlls[i].name, thunked_dlls[i].name + strlen(thunked_dlls[i].name));
        if (lower.find(wide_name) != std::wstring::npos) return &thunked_dlls[i];
    }
    return nullptr;
}

/* Check if a file is an ARM PE (WinCE) executable by reading its PE header. */
bool IsArmPE(const std::wstring& host_path) {
    HANDLE f = CreateFileW(host_path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return false;
    uint8_t buf[512]; DWORD n = 0;
    ReadFile(f, buf, sizeof(buf), &n, NULL);
    CloseHandle(f);
    if (n < 0x40) return false;
    if (buf[0] != 'M' || buf[1] != 'Z') return false;
    uint32_t pe_off = *(uint32_t*)(buf + 0x3C);
    if (pe_off + 6 > n) return false;
    if (buf[pe_off] != 'P' || buf[pe_off+1] != 'E') return false;
    uint16_t machine = *(uint16_t*)(buf + pe_off + 4);
    return (machine == 0x01C0 || machine == 0x01C2);
}
