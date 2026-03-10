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
    Thunk("CreateThread", 492, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* CreateThread(lpSA, stackSize, lpStartAddress, lpParameter, flags, lpThreadId)
           ARM calling convention: R0=lpSA, R1=stackSize, R2=lpStartAddress, R3=lpParameter
           Stack: [0]=flags, [1]=lpThreadId */
        uint32_t lpStartAddress = regs[2];
        uint32_t lpParameter = regs[3];
        uint32_t flags = ReadStackArg(regs, mem, 0);
        uint32_t lpThreadId = ReadStackArg(regs, mem, 1);
        LOG(API, "[API] CreateThread(startAddr=0x%08X, param=0x%08X, flags=0x%X)\n",
            lpStartAddress, lpParameter, flags);

        if (!lpStartAddress) {
            LOG(API, "[API]   CreateThread: null start address\n");
            regs[0] = 0; return true;
        }

        /* Capture everything the new thread needs */
        struct ThreadStartInfo {
            uint32_t start_addr;
            uint32_t parameter;
            EmulatedMemory* mem;
            Win32Thunks* thunks;
            uint32_t sentinel;
        };
        auto* info = new ThreadStartInfo{
            lpStartAddress, lpParameter, &mem, this, 0xCAFEC000
        };

        DWORD realThreadId = 0;
        HANDLE hThread = ::CreateThread(NULL, 0,
            [](LPVOID param) -> DWORD {
                auto* info = (ThreadStartInfo*)param;
                int thread_idx = g_next_thread_index.fetch_add(1);

                /* Create per-thread context */
                ThreadContext ctx;
                ctx.marshal_base = 0x3F000000 + (thread_idx + 1) * 0x10000;
                t_ctx = &ctx;

                /* Allocate per-thread stack in emulated memory */
                uint32_t stack_size = 0x100000; /* 1MB */
                uint32_t stack_bottom = 0x02000000 + thread_idx * stack_size;
                info->mem->Alloc(stack_bottom, stack_size);
                uint32_t stack_top = stack_bottom + stack_size - 16;

                /* Initialize per-thread KData */
                InitThreadKData(&ctx, *info->mem, GetCurrentThreadId());
                EmulatedMemory::kdata_override = ctx.kdata;

                /* Set up CPU */
                ArmCpu& cpu = ctx.cpu;
                cpu.mem = info->mem;
                cpu.thunk_handler = [thunks = info->thunks](
                        uint32_t addr, uint32_t* regs, EmulatedMemory& m) -> bool {
                    if (addr == 0xDEADDEAD) {
                        LOG(EMU, "[EMU] Thread returned with code %d\n", regs[0]);
                        return true; /* will cause halted check */
                    }
                    if (addr == 0xCAFEC000) {
                        regs[15] = 0xCAFEC000;
                        return true;
                    }
                    return thunks->HandleThunk(addr, regs, m);
                };

                /* Build callback_executor for this thread */
                MakeCallbackExecutor(&ctx, *info->mem, *info->thunks, info->sentinel);

                /* Allocate marshal buffer page */
                info->mem->Alloc(ctx.marshal_base, 0x10000);

                /* Set up initial registers */
                cpu.r[0] = info->parameter;
                cpu.r[REG_SP] = stack_top;
                cpu.r[REG_LR] = 0xDEADDEAD;
                if (info->start_addr & 1) {
                    cpu.cpsr |= PSR_T;
                    cpu.r[REG_PC] = info->start_addr & ~1u;
                } else {
                    cpu.r[REG_PC] = info->start_addr;
                }
                cpu.cpsr |= 0x13; /* SVC mode */

                LOG(API, "[THREAD] Started thread %d: PC=0x%08X SP=0x%08X param=0x%08X\n",
                    thread_idx, cpu.r[REG_PC], stack_top, info->parameter);
                delete info;

                /* Run the thread */
                cpu.Run();

                LOG(API, "[THREAD] Thread %d exited with R0=0x%X\n",
                    thread_idx, cpu.r[0]);
                t_ctx = nullptr;
                EmulatedMemory::kdata_override = nullptr;
                return cpu.r[0];
            },
            info,
            (flags & CREATE_SUSPENDED) ? CREATE_SUSPENDED : 0,
            &realThreadId);

        if (!hThread) {
            LOG(API, "[API]   CreateThread FAILED (err=%lu)\n", GetLastError());
            delete info;
            regs[0] = 0;
            return true;
        }

        LOG(API, "[API]   CreateThread: real thread handle=0x%p tid=%u\n",
            hThread, realThreadId);
        if (lpThreadId) mem.Write32(lpThreadId, realThreadId);
        regs[0] = WrapHandle(hThread);
        return true;
    });
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
        std::wstring mapped_image = image.empty() ? L"" : MapWinCEPath(image);
        /* If image is an ARM PE, spawn cerf.exe to run it */
        if (!mapped_image.empty() && IsArmPE(mapped_image)) {
            /* Build cerf.exe command line: cerf.exe <mapped_image_path> */
            wchar_t cerf_path[MAX_PATH];
            GetModuleFileNameW(NULL, cerf_path, MAX_PATH);
            std::wstring cerf_cmdline = L"\"";
            cerf_cmdline += cerf_path;
            cerf_cmdline += L"\" \"";
            cerf_cmdline += mapped_image;
            cerf_cmdline += L"\"";
            LOG(API, "[API]   -> ARM PE detected, spawning cerf: %ls\n", cerf_cmdline.c_str());
            STARTUPINFOW si = {}; si.cb = sizeof(si);
            PROCESS_INFORMATION pi = {};
            std::vector<wchar_t> cmd_buf(cerf_cmdline.begin(), cerf_cmdline.end());
            cmd_buf.push_back(0);
            BOOL ret = CreateProcessW(cerf_path, cmd_buf.data(),
                NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
            if (ret && procinfo_ptr) {
                mem.Write32(procinfo_ptr + 0x00, WrapHandle(pi.hProcess));
                mem.Write32(procinfo_ptr + 0x04, WrapHandle(pi.hThread));
                mem.Write32(procinfo_ptr + 0x08, pi.dwProcessId);
                mem.Write32(procinfo_ptr + 0x0C, pi.dwThreadId);
            }
            LOG(API, "[API]   -> %s (pid=%d)\n", ret ? "OK" : "FAILED", ret ? pi.dwProcessId : 0);
            regs[0] = ret;
        } else {
            /* Not an ARM PE — try native CreateProcessW */
            STARTUPINFOW si = {}; si.cb = sizeof(si);
            PROCESS_INFORMATION pi = {};
            std::vector<wchar_t> cmdline_buf(cmdline.begin(), cmdline.end());
            cmdline_buf.push_back(0);
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
        }
        return true;
    });
    Thunk("TerminateThread", 491, stub0("TerminateThread"));
    Thunk("ResumeThread", 500, stub0("ResumeThread"));
    Thunk("SetThreadPriority", 514, stub0("SetThreadPriority"));
    Thunk("GetExitCodeProcess", 519, stub0("GetExitCodeProcess"));
    Thunk("OpenProcess", 509, stub0("OpenProcess"));
    Thunk("WaitForMultipleObjects", 498, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* WaitForMultipleObjects(nCount, lpHandles, bWaitAll, dwMilliseconds) */
        uint32_t nCount = regs[0];
        uint32_t lpHandles = regs[1];
        BOOL bWaitAll = regs[2];
        uint32_t dwMilliseconds = regs[3];
        if (nCount == 0 || nCount > 64 || !lpHandles) {
            LOG(API, "[API] WaitForMultipleObjects(n=%u) -> WAIT_FAILED (bad args)\n", nCount);
            regs[0] = WAIT_FAILED;
            return true;
        }
        HANDLE handles[64];
        for (uint32_t i = 0; i < nCount; i++) {
            uint32_t raw = mem.Read32(lpHandles + i * 4);
            handles[i] = (HANDLE)(intptr_t)(int32_t)raw;
            LOG(API, "[API]   WaitForMulti handle[%u]: raw=0x%08X -> native=%p\n",
                i, raw, handles[i]);
        }
        /* With real threads, no need to cap timeout — each thread has its own message pump */
        DWORD result = WaitForMultipleObjects(nCount, handles, bWaitAll, dwMilliseconds);
        if (result == WAIT_FAILED) {
            LOG(API, "[API] WaitForMultipleObjects(n=%u, waitAll=%d, ms=%u) -> WAIT_FAILED (err=%lu)\n",
                nCount, bWaitAll, dwMilliseconds, GetLastError());
        } else {
            LOG(API, "[API] WaitForMultipleObjects(n=%u, waitAll=%d, ms=%u) -> 0x%X\n",
                nCount, bWaitAll, dwMilliseconds, result);
        }
        regs[0] = result;
        return true;
    });

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
