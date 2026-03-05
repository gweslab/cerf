/* Virtual Filesystem: maps WinCE paths <-> host filesystem paths.
   Two-layer mapping:
   - Single-letter root dirs (\c\..., \d\...) pass through to real host drives (C:\..., D:\...)
   - Everything else (\Windows\..., \My Documents\...) resolves under devices/<device>/fs/
   Drive letter syntax (C:\foo) is equivalent to \c\foo — both map to the real host C:\foo. */
#define _CRT_SECURE_NO_WARNINGS
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <fstream>
#include <algorithm>

void Win32Thunks::InitVFS(const std::string& device_override) {
    /* Determine cerf.exe directory */
    char cerf_path[MAX_PATH];
    ::GetModuleFileNameA(NULL, cerf_path, MAX_PATH);
    std::string cerf_str(cerf_path);
    size_t last_sep = cerf_str.find_last_of("\\/");
    if (last_sep != std::string::npos)
        cerf_dir = cerf_str.substr(0, last_sep + 1);
    else
        cerf_dir = "";

    /* Read cerf.ini to get device name */
    std::string ini_path = cerf_dir + "cerf.ini";
    std::ifstream ini(ini_path);
    if (ini.is_open()) {
        std::string line;
        while (std::getline(ini, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.substr(0, 7) == "device=") {
                device_name = line.substr(7);
                /* Trim whitespace */
                while (!device_name.empty() && (device_name.back() == ' ' || device_name.back() == '\t'))
                    device_name.pop_back();
            }
            if (line.substr(0, 18) == "fake_screen_width=") {
                int v = atoi(line.substr(18).c_str());
                if (v > 0) screen_width = (uint32_t)v;
            }
            if (line.substr(0, 19) == "fake_screen_height=") {
                int v = atoi(line.substr(19).c_str());
                if (v > 0) screen_height = (uint32_t)v;
            }
            if (line.substr(0, 23) == "fake_screen_resolution=") {
                std::string val = line.substr(23);
                while (!val.empty() && (val.back() == ' ' || val.back() == '\t'))
                    val.pop_back();
                fake_screen_resolution = (val != "false" && val != "0" && val != "no");
            }
        }
    }
    /* CLI override takes priority */
    if (!device_override.empty()) {
        device_name = device_override;
    }
    if (device_name.empty()) {
        LOG_ERR("[VFS] FATAL: No device configured. Set device= in cerf.ini or use --device=NAME.\n");
        LOG_ERR("[VFS] Expected cerf.ini at: %s\n", ini_path.c_str());
        ExitProcess(1);
    }

    device_fs_root = cerf_dir + "devices\\" + device_name + "\\fs\\";
    device_dir = cerf_dir + "devices\\" + device_name + "\\";

    LOG(VFS, "[VFS] Device: %s\n", device_name.c_str());
    LOG(VFS, "[VFS] Device FS root: %s\n", device_fs_root.c_str());

    /* Also set wince_sys_dir for ARM DLL loading compatibility —
       it now points to the Windows subdirectory of the device fs */
    wince_sys_dir = device_fs_root + "Windows\\";

    /* Now that device_dir is set, initialize the WinCE system font from registry.
       This was deferred from the constructor because LoadRegistry needs device_dir. */
    InitWceSysFont();
}

/* Helper: check if a character is a drive letter */
static bool IsDriveLetter(wchar_t c) {
    return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z');
}

/* Map a WinCE path to a host filesystem path.
   Rules:
   - \c\foo\bar         -> C:\foo\bar           (single-letter root = host drive pass-through)
   - \d\                -> D:\                   (any drive letter)
   - C:\foo\bar         -> C:\foo\bar           (drive letter syntax = same pass-through)
   - \Windows\foo       -> <device_fs_root>\Windows\foo    (multi-letter = device fs)
   - \My Documents\x    -> <device_fs_root>\My Documents\x
   - relative           -> <device_fs_root>\relative
   Empty path returns empty. */
std::wstring Win32Thunks::MapWinCEPath(const std::wstring& wce_path) {
    if (wce_path.empty()) return wce_path;

    /* Convert device_fs_root to wide string */
    std::wstring wide_fs_root;
    for (char c : device_fs_root) wide_fs_root += (wchar_t)c;

    /* Drive letter path (e.g. C:\foo\bar) -> real host C:\foo\bar */
    if (wce_path.size() >= 2 && wce_path[1] == L':' && IsDriveLetter(wce_path[0])) {
        LOG(VFS, "[VFS] Map '%ls' -> '%ls' (drive pass-through)\n", wce_path.c_str(), wce_path.c_str());
        return wce_path;
    }

    /* Root-relative path (starts with \ or /) */
    if (wce_path[0] == L'\\' || wce_path[0] == L'/') {
        std::wstring after_root = wce_path.substr(1); /* strip leading separator */

        /* Check for single-letter root directory = drive letter pass-through.
           \c\foo -> C:\foo, \d -> D:\, \c -> C:\ */
        if (!after_root.empty() && IsDriveLetter(after_root[0])) {
            bool is_drive = false;
            if (after_root.size() == 1)  /* just "\c" */
                is_drive = true;
            else if (after_root[1] == L'\\' || after_root[1] == L'/')  /* "\c\..." */
                is_drive = true;

            if (is_drive) {
                wchar_t drive = after_root[0];
                if (drive >= L'a' && drive <= L'z') drive -= 32; /* uppercase for host */
                std::wstring rest = (after_root.size() > 1) ? after_root.substr(1) : L"\\";
                std::wstring result = std::wstring(1, drive) + L":" + rest;
                LOG(VFS, "[VFS] Map '%ls' -> '%ls' (drive pass-through)\n", wce_path.c_str(), result.c_str());
                return result;
            }
        }

        /* Multi-letter root directory -> device fs */
        std::wstring result = wide_fs_root + after_root;
        LOG(VFS, "[VFS] Map '%ls' -> '%ls'\n", wce_path.c_str(), result.c_str());
        return result;
    }

    /* Relative path — resolve under fs root */
    std::wstring result = wide_fs_root + wce_path;
    LOG(VFS, "[VFS] Map '%ls' -> '%ls'\n", wce_path.c_str(), result.c_str());
    return result;
}

/* Reverse mapping: convert a host filesystem path back to a WinCE-style path.
   - Host drive paths (C:\foo) -> \c\foo  (lowercase drive letter dir)
   - Paths under device_fs_root -> \relative
   - Otherwise return original path unchanged. */
std::wstring Win32Thunks::MapHostToWinCE(const std::wstring& host_path) {
    if (host_path.empty()) return host_path;

    /* Host drive path (e.g. C:\foo\bar) -> \c\foo\bar */
    if (host_path.size() >= 2 && host_path[1] == L':' && IsDriveLetter(host_path[0])) {
        wchar_t drive = host_path[0];
        if (drive >= L'A' && drive <= L'Z') drive += 32; /* lowercase */
        std::wstring rest = (host_path.size() > 2) ? host_path.substr(2) : L"";
        return L"\\" + std::wstring(1, drive) + rest;
    }

    std::wstring wide_fs_root;
    for (char c : device_fs_root) wide_fs_root += (wchar_t)c;

    /* Case-insensitive prefix match against device fs root */
    if (host_path.size() >= wide_fs_root.size()) {
        bool match = true;
        for (size_t i = 0; i < wide_fs_root.size(); i++) {
            wchar_t a = host_path[i], b = wide_fs_root[i];
            if (a >= L'A' && a <= L'Z') a += 32;
            if (b >= L'A' && b <= L'Z') b += 32;
            if (a == L'/') a = L'\\';
            if (b == L'/') b = L'\\';
            if (a != b) { match = false; break; }
        }
        if (match) {
            std::wstring relative = host_path.substr(wide_fs_root.size());
            return L"\\" + relative;
        }
    }

    /* Not under our fs root — return as-is */
    return host_path;
}

void Win32Thunks::RegisterVfsHandlers() {
    /* GetTempPathW(nBufferLength, lpBuffer) — return \Temp */
    Thunk("GetTempPathW", 162, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t buf_len = regs[0];
        uint32_t buf_addr = regs[1];
        const wchar_t* temp_path = L"\\Temp\\";
        size_t len = wcslen(temp_path);
        LOG(API, "[API] GetTempPathW(bufLen=%d) -> '%ls'\n", buf_len, temp_path);
        if (buf_addr && buf_len > len) {
            for (size_t i = 0; i <= len; i++)
                mem.Write16(buf_addr + (uint32_t)i * 2, temp_path[i]);
            /* Ensure the Temp directory exists on the host */
            std::wstring host_temp = MapWinCEPath(L"\\Temp");
            CreateDirectoryW(host_temp.c_str(), NULL);
        }
        regs[0] = (uint32_t)len;
        return true;
    });
}
