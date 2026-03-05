#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Process/thread thunks: CreateProcessW, CreateThread stubs, file mapping */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <vector>

void Win32Thunks::RegisterProcessHandlers() {
    auto stub0 = [](const char* name) -> ThunkHandler {
        return [name](uint32_t* regs, EmulatedMemory&) -> bool {
            LOG(API, "[API] [STUB] %s -> 0\n", name); regs[0] = 0; return true;
        };
    };
    Thunk("CreateThread", 492, stub0("CreateThread"));
    Thunk("CreateProcessW", 493, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t image_ptr = regs[0], cmdline_ptr = regs[1];
        uint32_t fdwCreate = ReadStackArg(regs, mem, 1);
        uint32_t curdir_ptr = ReadStackArg(regs, mem, 3);
        uint32_t procinfo_ptr = ReadStackArg(regs, mem, 5);
        std::wstring image, cmdline, curdir;
        if (image_ptr) image = ReadWStringFromEmu(mem, image_ptr);
        if (cmdline_ptr) cmdline = ReadWStringFromEmu(mem, cmdline_ptr);
        if (curdir_ptr) curdir = ReadWStringFromEmu(mem, curdir_ptr);
        LOG(API, "[API] CreateProcessW(image='%ls', cmdline='%ls', curdir='%ls', flags=0x%X)\n",
               image.c_str(), cmdline.c_str(), curdir.c_str(), fdwCreate);
        STARTUPINFOW si = {}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi = {};
        std::vector<wchar_t> cmdline_buf(cmdline.begin(), cmdline.end());
        cmdline_buf.push_back(0);
        std::wstring mapped_image = image.empty() ? L"" : MapWinCEPath(image);
        std::wstring mapped_curdir = curdir.empty() ? L"" : MapWinCEPath(curdir);
        BOOL ret = CreateProcessW(
            mapped_image.empty() ? NULL : mapped_image.c_str(),
            cmdline_buf.data(),
            NULL, NULL, FALSE, fdwCreate, NULL,
            mapped_curdir.empty() ? NULL : mapped_curdir.c_str(),
            &si, &pi);
        if (ret && procinfo_ptr) {
            mem.Write32(procinfo_ptr + 0x00, (uint32_t)(uintptr_t)pi.hProcess);
            mem.Write32(procinfo_ptr + 0x04, (uint32_t)(uintptr_t)pi.hThread);
            mem.Write32(procinfo_ptr + 0x08, pi.dwProcessId);
            mem.Write32(procinfo_ptr + 0x0C, pi.dwThreadId);
        }
        LOG(API, "[API]   -> %s (pid=%d)\n", ret ? "OK" : "FAILED", ret ? pi.dwProcessId : 0);
        regs[0] = ret;
        return true;
    });
    Thunk("TerminateThread", 491, stub0("TerminateThread"));
    Thunk("ResumeThread", 500, stub0("ResumeThread"));
    Thunk("SetThreadPriority", 514, stub0("SetThreadPriority"));
    Thunk("GetExitCodeProcess", 519, stub0("GetExitCodeProcess"));
    Thunk("OpenProcess", 509, stub0("OpenProcess"));
    Thunk("WaitForMultipleObjects", 498, stub0("WaitForMultipleObjects"));

    /* File mapping: read file contents into emulated memory */
    Thunk("CreateFileMappingW", 548, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HANDLE hFile = UnwrapHandle(regs[0]);
        uint32_t flProtect = regs[2];
        LOG(API, "[API] CreateFileMappingW(hFile=0x%08X, protect=0x%X)\n", regs[0], flProtect);
        if (hFile == INVALID_HANDLE_VALUE || hFile == NULL) {
            LOG(API, "[API]   -> FAILED (invalid file handle)\n");
            regs[0] = 0; return true;
        }
        DWORD file_size = GetFileSize(hFile, NULL);
        if (file_size == INVALID_FILE_SIZE || file_size == 0) {
            LOG(API, "[API]   -> FAILED (file size = 0x%X)\n", file_size);
            regs[0] = 0; return true;
        }
        /* Allocate emulated memory and read the file into it */
        static uint32_t next_mmap = 0x50000000;
        uint32_t alloc_size = (file_size + 0xFFF) & ~0xFFF;
        uint8_t* host_ptr = mem.Alloc(next_mmap, alloc_size);
        if (!host_ptr) {
            LOG(API, "[API]   -> FAILED (alloc)\n");
            regs[0] = 0; return true;
        }
        /* Save and restore file pointer */
        DWORD saved_pos = SetFilePointer(hFile, 0, NULL, FILE_CURRENT);
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        DWORD bytes_read = 0;
        ReadFile(hFile, host_ptr, file_size, &bytes_read, NULL);
        SetFilePointer(hFile, saved_pos, NULL, FILE_BEGIN);
        /* Store mapping info: use handle map with emu address as the data */
        uint32_t emu_addr = next_mmap;
        next_mmap += alloc_size;
        /* Pack mapping info: store in file_mappings map */
        file_mappings[WrapHandle((HANDLE)(uintptr_t)emu_addr)] = { emu_addr, file_size };
        uint32_t fake_handle = next_fake_handle - 1; /* last wrapped handle */
        LOG(API, "[API]   -> handle=0x%08X (mapped %u bytes at emu 0x%08X)\n",
            fake_handle, bytes_read, emu_addr);
        regs[0] = fake_handle;
        return true;
    });
    Thunk("MapViewOfFile", 549, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t mapping_handle = regs[0];
        uint32_t offset_high = regs[2], offset_low = regs[3];
        LOG(API, "[API] MapViewOfFile(handle=0x%08X, offset=0x%X:%08X)\n",
            mapping_handle, offset_high, offset_low);
        auto it = file_mappings.find(mapping_handle);
        if (it == file_mappings.end()) {
            LOG(API, "[API]   -> FAILED (unknown mapping)\n");
            regs[0] = 0; return true;
        }
        uint32_t addr = it->second.emu_addr + offset_low;
        LOG(API, "[API]   -> 0x%08X (size=%u)\n", addr, it->second.size);
        regs[0] = addr;
        return true;
    });
    Thunk("UnmapViewOfFile", 550, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] UnmapViewOfFile(0x%08X) -> 1\n", regs[0]);
        regs[0] = 1; return true;
    });
    /* CreateFileForMappingW - same as CreateFileW but used specifically before mapping */
    Thunk("CreateFileForMappingW", 1167, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring wce_path = ReadWStringFromEmu(mem, regs[0]);
        uint32_t access = regs[1], share = regs[2];
        uint32_t creation = ReadStackArg(regs, mem, 0), flags = ReadStackArg(regs, mem, 1);
        std::wstring host_path = MapWinCEPath(wce_path);
        HANDLE h = CreateFileW(host_path.c_str(), access, share, NULL, creation, flags, NULL);
        regs[0] = WrapHandle(h);
        LOG(API, "[API] CreateFileForMappingW('%ls') -> handle=0x%08X\n", wce_path.c_str(), regs[0]);
        return true;
    });
}
