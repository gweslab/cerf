/* Sync thunks: critical sections, interlocked ops, events, mutexes, semaphores, TLS */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>

void Win32Thunks::RegisterSyncHandlers() {
    /* Critical sections — real critical sections now that we have real threads */
    Thunk("InitializeCriticalSection", 2, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t addr = regs[0];
        CRITICAL_SECTION* cs = new CRITICAL_SECTION;
        InitializeCriticalSection(cs);
        std::lock_guard<std::mutex> lock(cs_map_mutex);
        cs_map[addr] = cs;
        return true;
    });
    Thunk("DeleteCriticalSection", 3, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t addr = regs[0];
        std::lock_guard<std::mutex> lock(cs_map_mutex);
        auto it = cs_map.find(addr);
        if (it != cs_map.end()) {
            DeleteCriticalSection(it->second);
            delete it->second;
            cs_map.erase(it);
        }
        return true;
    });
    Thunk("EnterCriticalSection", 4, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t addr = regs[0];
        CRITICAL_SECTION* cs = nullptr;
        {
            std::lock_guard<std::mutex> lock(cs_map_mutex);
            auto it = cs_map.find(addr);
            if (it != cs_map.end()) cs = it->second;
        }
        if (cs) EnterCriticalSection(cs);
        return true;
    });
    Thunk("LeaveCriticalSection", 5, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t addr = regs[0];
        CRITICAL_SECTION* cs = nullptr;
        {
            std::lock_guard<std::mutex> lock(cs_map_mutex);
            auto it = cs_map.find(addr);
            if (it != cs_map.end()) cs = it->second;
        }
        if (cs) LeaveCriticalSection(cs);
        return true;
    });
    Thunk("InitLocale", 8, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 1; return true; });
    /* Interlocked operations — use real atomic ops for thread safety.
       Identity-mapped memory means ARM pointers are valid native pointers. */
    Thunk("InterlockedIncrement", 10, [](uint32_t* regs, EmulatedMemory&) -> bool {
        volatile LONG* ptr = (volatile LONG*)(uintptr_t)regs[0];
        regs[0] = (uint32_t)InterlockedIncrement(ptr);
        return true;
    });
    ThunkOrdinal("InterlockedDecrement", 11);
    Thunk("InterlockedDecrement", [](uint32_t* regs, EmulatedMemory&) -> bool {
        volatile LONG* ptr = (volatile LONG*)(uintptr_t)regs[0];
        regs[0] = (uint32_t)InterlockedDecrement(ptr);
        return true;
    });
    Thunk("InterlockedExchange", 12, [](uint32_t* regs, EmulatedMemory&) -> bool {
        volatile LONG* ptr = (volatile LONG*)(uintptr_t)regs[0];
        regs[0] = (uint32_t)InterlockedExchange(ptr, (LONG)regs[1]);
        return true;
    });
    Thunk("InterlockedCompareExchange", 1492, [](uint32_t* regs, EmulatedMemory&) -> bool {
        volatile LONG* ptr = (volatile LONG*)(uintptr_t)regs[0];
        LONG original = InterlockedCompareExchange(ptr, (LONG)regs[1], (LONG)regs[2]);
        regs[0] = (uint32_t)original;
        return true;
    });
    Thunk("CreateEventW", 495, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HANDLE h = CreateEventW(NULL, regs[1], regs[2], NULL);
        regs[0] = (uint32_t)(uintptr_t)h;
        LOG(API, "[API] CreateEventW(manual=%d, initial=%d) -> handle=%p (arm=0x%08X)\n",
            regs[1], regs[2], h, regs[0]);
        return true;
    });
    Thunk("WaitForSingleObject", 497, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = WaitForSingleObject((HANDLE)(intptr_t)(int32_t)regs[0], regs[1]); return true;
    });
    Thunk("CloseHandle", 553, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t fake = regs[0]; HANDLE h = UnwrapHandle(fake);
        regs[0] = CloseHandle(h); RemoveHandle(fake); return true;
    });
    Thunk("CreateMutexW", 555, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)CreateMutexW(NULL, regs[1], NULL); return true;
    });
    Thunk("ReleaseMutex", 556, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ReleaseMutex((HANDLE)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("CreateSemaphoreW", 1238, [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* CreateSemaphoreW(lpSA, lInitialCount, lMaximumCount, lpName) */
        HANDLE h = CreateSemaphoreW(NULL, (LONG)regs[1], (LONG)regs[2], NULL);
        LOG(API, "[API] CreateSemaphoreW(init=%d, max=%d) -> 0x%p\n",
            (int)regs[1], (int)regs[2], h);
        regs[0] = (uint32_t)(uintptr_t)h;
        return true;
    });
    Thunk("ReleaseSemaphore", 1239, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LONG prev = 0;
        BOOL ok = ReleaseSemaphore((HANDLE)(intptr_t)(int32_t)regs[0], (LONG)regs[1], &prev);
        LOG(API, "[API] ReleaseSemaphore(0x%08X, count=%d) -> %d (prev=%d)\n",
            regs[0], (int)regs[1], ok, prev);
        regs[0] = ok;
        return true;
    });
    /* TLS — emulated via the KData page at 0xFFFFC800.
       WinCE ARM code can access TLS directly through memory:
         lpvTls = *(DWORD*)0xFFFFC800   (pointer to TLS slot array)
         value  = lpvTls[slot_index]     (read slot)
       TLS slot array at 0xFFFFC01C, set up in Win32Thunks constructor.
       Slots 0-3 reserved by WinCE; TlsCall allocates from 4 onward.
       Next-free counter stored at 0xFFFFC880 (KData padding area). */
    Thunk("TlsGetValue", 15, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t idx = regs[0];
        if (idx < 64) {
            regs[0] = mem.Read32(0xFFFFC01C + idx * 4);
        } else {
            regs[0] = 0;
        }
        SetLastError(ERROR_SUCCESS);
        LOG(API, "[API] TlsGetValue(%u) -> 0x%08X\n", idx, regs[0]);
        return true;
    });
    Thunk("TlsSetValue", 16, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t idx = regs[0];
        if (idx < 64) {
            mem.Write32(0xFFFFC01C + idx * 4, regs[1]);
            LOG(API, "[API] TlsSetValue(%u, 0x%08X) -> 1\n", idx, regs[1]);
            regs[0] = 1;
        } else {
            LOG(API, "[API] TlsSetValue(%u) -> 0 (out of range)\n", idx);
            regs[0] = 0;
        }
        return true;
    });
    /* TlsCall: allocates a TLS slot. Uses atomic counter shared across threads. */
    Thunk("TlsCall", 520, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t slot = next_tls_slot.fetch_add(1);
        if (slot < 64) {
            LOG(API, "[API] TlsCall() -> slot %u\n", slot);
            regs[0] = slot;
        } else {
            LOG(API, "[API] TlsCall() -> 0 (out of slots)\n");
            regs[0] = 0;
        }
        return true;
    });
}
