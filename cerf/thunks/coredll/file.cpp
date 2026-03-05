/* File I/O thunks: CreateFile, ReadFile, WriteFile, Find*, directory ops */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <vector>

/* State for root directory enumeration: after real host entries are exhausted,
   we inject synthetic entries for available drive letters (a-z). */
struct RootFindState {
    bool host_done = false;   /* true once real FindNextFileW returns FALSE */
    int next_drive = 0;       /* 0-25 = 'a'-'z', 26 = done */
    DWORD drive_mask = 0;     /* bitmask from GetLogicalDrives() */
};
static std::map<uint32_t, RootFindState> root_find_states; /* fake handle -> state */

/* WinCE FindFirstFile/FindNextFile never return "." and ".." entries.
   Skip them to match real WinCE behavior and prevent infinite recursion
   in apps that recursively traverse directories. */
static bool IsDotOrDotDot(const wchar_t* name) {
    return (name[0] == L'.' && (name[1] == 0 || (name[1] == L'.' && name[2] == 0)));
}

/* Check if a WinCE search pattern targets the root directory (e.g. \* or \*.* ) */
static bool IsRootPattern(const std::wstring& wce_pattern) {
    if (wce_pattern.size() < 2) return false;
    if (wce_pattern[0] != L'\\' && wce_pattern[0] != L'/') return false;
    /* \* or \*.* */
    std::wstring after = wce_pattern.substr(1);
    return (after == L"*" || after == L"*.*");
}

/* Build a synthetic WIN32_FIND_DATAW for a drive letter directory */
static WIN32_FIND_DATAW MakeDriveEntry(char drive_letter) {
    WIN32_FIND_DATAW fd = {};
    fd.dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
    fd.cFileName[0] = (wchar_t)drive_letter;
    fd.cFileName[1] = 0;
    return fd;
}

void Win32Thunks::RegisterFileHandlers() {
    Thunk("CreateFileW", 168, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring wce_path = ReadWStringFromEmu(mem, regs[0]);
        uint32_t access = regs[1], share = regs[2];
        uint32_t creation = ReadStackArg(regs, mem, 0), flags = ReadStackArg(regs, mem, 1);
        std::wstring host_path = MapWinCEPath(wce_path);
        HANDLE h = CreateFileW(host_path.c_str(), access, share, NULL, creation, flags, NULL);
        regs[0] = WrapHandle(h);
        LOG(API, "[API] CreateFileW('%ls') -> handle=0x%08X\n", wce_path.c_str(), regs[0]);
        return true;
    });
    Thunk("ReadFile", 170, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HANDLE h = UnwrapHandle(regs[0]);
        uint32_t buf_addr = regs[1], bytes_to_read = regs[2], bytes_read_addr = regs[3];
        if (bytes_to_read > 64 * 1024 * 1024) {
            if (bytes_read_addr) mem.Write32(bytes_read_addr, 0);
            SetLastError(ERROR_INVALID_PARAMETER); regs[0] = 0; return true;
        }
        std::vector<uint8_t> buf(bytes_to_read);
        DWORD bytes_read = 0;
        BOOL ret = ReadFile(h, buf.data(), bytes_to_read, &bytes_read, NULL);
        if (ret && bytes_read > 0) {
            for (DWORD i = 0; i < bytes_read; i++) mem.Write8(buf_addr + i, buf[i]);
        }
        if (bytes_read_addr) mem.Write32(bytes_read_addr, bytes_read);
        LOG(API, "[API] ReadFile(h=0x%08X, %u bytes) -> %d (read=%u)\n",
            regs[0], bytes_to_read, ret, bytes_read);
        regs[0] = ret; return true;
    });
    Thunk("WriteFile", 171, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HANDLE h = UnwrapHandle(regs[0]);
        uint32_t buf_addr = regs[1], bytes_to_write = regs[2], bytes_written_addr = regs[3];
        if (bytes_to_write > 64 * 1024 * 1024) {
            if (bytes_written_addr) mem.Write32(bytes_written_addr, 0);
            SetLastError(ERROR_INVALID_PARAMETER); regs[0] = 0; return true;
        }
        std::vector<uint8_t> buf(bytes_to_write);
        for (uint32_t i = 0; i < bytes_to_write; i++) buf[i] = mem.Read8(buf_addr + i);
        DWORD bytes_written = 0;
        BOOL ret = WriteFile(h, buf.data(), bytes_to_write, &bytes_written, NULL);
        if (bytes_written_addr) mem.Write32(bytes_written_addr, bytes_written);
        regs[0] = ret; return true;
    });
    Thunk("GetFileSize", 172, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HANDLE h = UnwrapHandle(regs[0]);
        DWORD high = 0;
        DWORD size = GetFileSize(h, regs[1] ? &high : NULL);
        if (regs[1]) mem.Write32(regs[1], high);
        regs[0] = size; return true;
    });
    Thunk("SetFilePointer", 173, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HANDLE h = UnwrapHandle(regs[0]);
        LONG dist = (LONG)regs[1]; uint32_t high_addr = regs[2]; DWORD method = regs[3];
        LONG high = 0;
        if (high_addr) high = (LONG)mem.Read32(high_addr);
        DWORD result = SetFilePointer(h, dist, high_addr ? &high : NULL, method);
        if (high_addr) mem.Write32(high_addr, (uint32_t)high);
        regs[0] = result; return true;
    });
    Thunk("GetFileAttributesW", 166, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring wce_path = ReadWStringFromEmu(mem, regs[0]);
        std::wstring host_path = MapWinCEPath(wce_path);
        regs[0] = GetFileAttributesW(host_path.c_str());
        LOG(API, "[API] GetFileAttributesW('%ls' -> '%ls') -> 0x%08X\n", wce_path.c_str(), host_path.c_str(), regs[0]);
        return true;
    });
    Thunk("DeleteFileW", 165, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring wce_path = ReadWStringFromEmu(mem, regs[0]);
        regs[0] = DeleteFileW(MapWinCEPath(wce_path).c_str());
        return true;
    });
    Thunk("MoveFileW", 163, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring src = ReadWStringFromEmu(mem, regs[0]);
        std::wstring dst = ReadWStringFromEmu(mem, regs[1]);
        regs[0] = MoveFileW(MapWinCEPath(src).c_str(), MapWinCEPath(dst).c_str());
        return true;
    });
    Thunk("CreateDirectoryW", 160, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring wce_path = ReadWStringFromEmu(mem, regs[0]);
        regs[0] = CreateDirectoryW(MapWinCEPath(wce_path).c_str(), NULL);
        return true;
    });
    Thunk("RemoveDirectoryW", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring wce_path = ReadWStringFromEmu(mem, regs[0]);
        regs[0] = RemoveDirectoryW(MapWinCEPath(wce_path).c_str());
        return true;
    });
    Thunk("FindFirstFileW", 167, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring wce_pattern = ReadWStringFromEmu(mem, regs[0]);
        uint32_t find_data_addr = regs[1];
        bool is_root = IsRootPattern(wce_pattern);
        std::wstring host_pattern = MapWinCEPath(wce_pattern);
        WIN32_FIND_DATAW fd = {};
        HANDLE h = FindFirstFileW(host_pattern.c_str(), &fd);
        /* Skip "." and ".." — WinCE never returns these */
        while (h != INVALID_HANDLE_VALUE && IsDotOrDotDot(fd.cFileName)) {
            if (!FindNextFileW(h, &fd)) {
                FindClose(h);
                h = INVALID_HANDLE_VALUE;
                SetLastError(ERROR_NO_MORE_FILES);
            }
        }
        if (h != INVALID_HANDLE_VALUE) WriteFindDataToEmu(mem, find_data_addr, fd);
        uint32_t fake = WrapHandle(h);
        /* Track root-level enumerations so we can inject drive letters later */
        if (is_root) {
            RootFindState state;
            state.drive_mask = GetLogicalDrives();
            root_find_states[fake] = state;
        }
        regs[0] = fake;
        return true;
    });
    Thunk("FindNextFileW", 181, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t fake = regs[0];
        HANDLE h = UnwrapHandle(fake);
        auto it = root_find_states.find(fake);
        /* Non-root enumeration: simple pass-through */
        if (it == root_find_states.end()) {
            WIN32_FIND_DATAW fd = {};
            BOOL ret = FindNextFileW(h, &fd);
            /* Skip "." and ".." — WinCE never returns these */
            while (ret && IsDotOrDotDot(fd.cFileName))
                ret = FindNextFileW(h, &fd);
            if (ret) WriteFindDataToEmu(mem, regs[1], fd);
            regs[0] = ret; return true;
        }
        /* Root enumeration: first exhaust real host entries, then inject drives */
        RootFindState& state = it->second;
        if (!state.host_done) {
            WIN32_FIND_DATAW fd = {};
            BOOL ret = FindNextFileW(h, &fd);
            /* Skip "." and ".." — WinCE never returns these */
            while (ret && IsDotOrDotDot(fd.cFileName))
                ret = FindNextFileW(h, &fd);
            if (ret) {
                WriteFindDataToEmu(mem, regs[1], fd);
                regs[0] = TRUE; return true;
            }
            state.host_done = true;
        }
        /* Inject drive letter directories */
        while (state.next_drive < 26) {
            int d = state.next_drive++;
            if (state.drive_mask & (1 << d)) {
                WIN32_FIND_DATAW fd = MakeDriveEntry('a' + d);
                WriteFindDataToEmu(mem, regs[1], fd);
                regs[0] = TRUE; return true;
            }
        }
        /* All done */
        SetLastError(ERROR_NO_MORE_FILES);
        regs[0] = FALSE; return true;
    });
    Thunk("FindClose", 180, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t fake = regs[0];
        HANDLE h = UnwrapHandle(fake);
        regs[0] = FindClose(h);
        RemoveHandle(fake);
        root_find_states.erase(fake);
        return true;
    });
    Thunk("GetFileTime", 176, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HANDLE h = UnwrapHandle(regs[0]);
        FILETIME ct, at, wt;
        BOOL ret = GetFileTime(h, regs[1] ? &ct : NULL, regs[2] ? &at : NULL, regs[3] ? &wt : NULL);
        if (ret) {
            if (regs[1]) { mem.Write32(regs[1], ct.dwLowDateTime); mem.Write32(regs[1]+4, ct.dwHighDateTime); }
            if (regs[2]) { mem.Write32(regs[2], at.dwLowDateTime); mem.Write32(regs[2]+4, at.dwHighDateTime); }
            if (regs[3]) { mem.Write32(regs[3], wt.dwLowDateTime); mem.Write32(regs[3]+4, wt.dwHighDateTime); }
        }
        LOG(API, "[API] GetFileTime(0x%08X) -> %d\n", regs[0], ret);
        regs[0] = ret; return true;
    });
    Thunk("FileTimeToLocalFileTime", 21, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        FILETIME ft_in, ft_out;
        ft_in.dwLowDateTime = mem.Read32(regs[0]);
        ft_in.dwHighDateTime = mem.Read32(regs[0] + 4);
        BOOL ret = FileTimeToLocalFileTime(&ft_in, &ft_out);
        if (ret && regs[1]) {
            mem.Write32(regs[1], ft_out.dwLowDateTime);
            mem.Write32(regs[1] + 4, ft_out.dwHighDateTime);
        }
        regs[0] = ret; return true;
    });
    Thunk("FileTimeToSystemTime", 20, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        FILETIME ft;
        ft.dwLowDateTime = mem.Read32(regs[0]);
        ft.dwHighDateTime = mem.Read32(regs[0] + 4);
        SYSTEMTIME st;
        BOOL ret = FileTimeToSystemTime(&ft, &st);
        if (ret && regs[1]) {
            mem.Write16(regs[1]+0, st.wYear); mem.Write16(regs[1]+2, st.wMonth);
            mem.Write16(regs[1]+4, st.wDayOfWeek); mem.Write16(regs[1]+6, st.wDay);
            mem.Write16(regs[1]+8, st.wHour); mem.Write16(regs[1]+10, st.wMinute);
            mem.Write16(regs[1]+12, st.wSecond); mem.Write16(regs[1]+14, st.wMilliseconds);
        }
        regs[0] = ret; return true;
    });
    /* Ordinal-only entries */
    ThunkOrdinal("CopyFileW", 164);
    ThunkOrdinal("GetTempPathW", 162);
    ThunkOrdinal("FlushFileBuffers", 175);
    ThunkOrdinal("SetFileTime", 177);
    ThunkOrdinal("DeleteAndRenameFile", 183);
    Thunk("GetDiskFreeSpaceExW", 184, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring path = ReadWStringFromEmu(mem, regs[0]);
        std::wstring mapped = MapWinCEPath(path);
        ULARGE_INTEGER freeCaller = {}, totalBytes = {}, totalFree = {};
        BOOL ret = GetDiskFreeSpaceExW(mapped.c_str(),
            regs[1] ? &freeCaller : NULL,
            regs[2] ? &totalBytes : NULL,
            regs[3] ? &totalFree : NULL);
        if (ret) {
            if (regs[1]) { mem.Write32(regs[1], freeCaller.LowPart); mem.Write32(regs[1]+4, freeCaller.HighPart); }
            if (regs[2]) { mem.Write32(regs[2], totalBytes.LowPart); mem.Write32(regs[2]+4, totalBytes.HighPart); }
            if (regs[3]) { mem.Write32(regs[3], totalFree.LowPart); mem.Write32(regs[3]+4, totalFree.HighPart); }
        }
        LOG(API, "[API] GetDiskFreeSpaceExW('%ls') -> %d\n", path.c_str(), ret);
        regs[0] = ret;
        return true;
    });
    Thunk("SetFileAttributesW", 169, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring path = ReadWStringFromEmu(mem, regs[0]);
        std::wstring mapped = MapWinCEPath(path);
        LOG(API, "[API] SetFileAttributesW('%ls', 0x%X)\n", path.c_str(), regs[1]);
        regs[0] = SetFileAttributesW(mapped.c_str(), regs[1]);
        return true;
    });
    Thunk("FindFirstChangeNotificationW", 1682, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring path = ReadWStringFromEmu(mem, regs[0]);
        std::wstring mapped = MapWinCEPath(path);
        LOG(API, "[API] FindFirstChangeNotificationW('%ls', subtree=%d, filter=0x%X)\n",
            path.c_str(), regs[1], regs[2]);
        HANDLE h = FindFirstChangeNotificationW(mapped.c_str(), regs[1], regs[2]);
        regs[0] = WrapHandle(h);
        return true;
    });
}
