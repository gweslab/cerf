/* Memory allocation thunks: VirtualAlloc, Heap*, Local*, malloc/free */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <cstring>
#include <algorithm>

/* All allocator bases MUST be below 0x02000000 (32MB slot boundary).
   WinCE ARM code applies slot masking (AND addr, #0x01FFFFFF) to pointers.
   Any address >= 0x02000000 gets corrupted to a different address.
   Address space layout (non-overlapping ranges):
     VirtualAlloc:  0x00200000  (grows up, ~6MB for app VirtualAlloc calls)
     LocalAlloc:    0x00800000  (grows up, ~2MB for small heap allocations)
     LocalReAlloc:  0x00A00000  (grows up, ~2MB for reallocation buffers)
     HeapAlloc:     0x00C00000  (grows up, ~3MB for heap blocks)
     Stack:         0x00F00000-0x01000000  (1MB, grows down from STACK_BASE)
     HeapReAlloc:   0x01000000  (grows up, ~1MB for heap realloc)
     malloc etc:    0x01100000  (grows up, remaining space to 0x02000000)
   NOTE: Keep ranges well-separated to avoid address collisions.
   IMPORTANT: 0x00400000 is NOT available — occupied by system on x64 Windows. */

void Win32Thunks::RegisterMemoryHandlers() {
    /* Pre-reserve address ranges for each allocator so that page-by-page
       commits within these ranges succeed (Windows requires 64KB-aligned
       addresses for MEM_RESERVE, but MEM_COMMIT works within reservations). */
    mem.Reserve(0x00200000, 0x00600000); /* VirtualAlloc: 0x00200000-0x007FFFFF (6MB) */
    mem.Reserve(0x00800000, 0x00200000); /* LocalAlloc:   0x00800000-0x009FFFFF (2MB) */
    mem.Reserve(0x00A00000, 0x00200000); /* LocalReAlloc: 0x00A00000-0x00BFFFFF (2MB) */
    mem.Reserve(0x00C00000, 0x00300000); /* HeapAlloc:    0x00C00000-0x00EFFFFF (3MB) */
    /* Stack at 0x00F00000-0x01000000 is reserved by AllocStack() */
    mem.Reserve(0x01000000, 0x00100000); /* HeapReAlloc:  0x01000000-0x010FFFFF (1MB) */
    mem.Reserve(0x01100000, 0x00F00000); /* malloc etc:   0x01100000-0x01FFFFFF (15MB) */
    mem.Reserve(0x3F000000, 0x00010000); /* Marshaling scratch buffers (callbacks/dlgproc) */

    Thunk("VirtualAlloc", 524, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t addr_arg = regs[0], size = regs[1];
        static uint32_t next_valloc = 0x00200000;
        uint32_t base = (addr_arg != 0) ? addr_arg : next_valloc;
        uint8_t* ptr = mem.Alloc(base, size, regs[3]);
        if (ptr) {
            if (addr_arg == 0) next_valloc = base + ((size + 0xFFF) & ~0xFFF);
            regs[0] = base;
        } else { regs[0] = 0; }
        LOG(API, "[API] VirtualAlloc(0x%08X, 0x%X) -> 0x%08X\n", addr_arg, size, regs[0]);
        return true;
    });
    Thunk("VirtualFree", 525, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[STUB] VirtualFree(0x%08X) -> 1 (leak)\n", regs[0]);
        regs[0] = 1; return true;
    });
    Thunk("LocalAlloc", 33, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t flags = regs[0], size = regs[1];
        static uint32_t next_local = 0x00800000;
        uint8_t* ptr = mem.Alloc(next_local, size);
        if (ptr) {
            if (flags & 0x40) memset(ptr, 0, size);
            regs[0] = next_local;
            next_local += (size + 0xFFF) & ~0xFFF;
        } else { regs[0] = 0; }
        return true;
    });
    thunk_handlers["LocalAllocTrace"] = thunk_handlers["LocalAlloc"];
    Thunk("LocalReAlloc", 34, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t old_ptr = regs[0], new_size = regs[1], flags = regs[2];
        static uint32_t next_lrealloc = 0x00A00000;
        uint8_t* new_host = mem.Alloc(next_lrealloc, new_size);
        /* LMEM_ZEROINIT: zero new buffer BEFORE copying old data on top */
        if ((flags & 0x40) && new_host) memset(new_host, 0, new_size);
        uint8_t* old_host = mem.Translate(old_ptr);
        if (old_host && new_host) memcpy(new_host, old_host, std::min(new_size, (uint32_t)0x1000));
        regs[0] = next_lrealloc;
        next_lrealloc += (new_size + 0xFFF) & ~0xFFF;
        return true;
    });
    Thunk("LocalFree", 36, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0; return true;
    });
    Thunk("LocalSize", 35, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[STUB] LocalSize(0x%08X) -> 0x1000\n", regs[0]);
        regs[0] = 0x1000; return true;
    });
    Thunk("GetProcessHeap", 50, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0xDEAD0001; return true;
    });
    auto heapAllocImpl = [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t size_arg = regs[2];
        static uint32_t next_heap = 0x00C00000;
        mem.Alloc(next_heap, size_arg);
        regs[0] = next_heap;
        next_heap += (size_arg + 0xFFF) & ~0xFFF;
        return true;
    };
    Thunk("HeapAlloc", 46, heapAllocImpl);
    Thunk("HeapAllocTrace", 20, heapAllocImpl);
    Thunk("HeapCreate", 44, [](uint32_t* regs, EmulatedMemory&) -> bool {
        static uint32_t next_handle = 0xDEAD0002;
        regs[0] = next_handle++;
        return true;
    });
    Thunk("HeapFree", 49, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 1; return true;
    });
    thunk_handlers["HeapDestroy"] = thunk_handlers["HeapFree"];
    Thunk("HeapReAlloc", 47, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t old_ptr = regs[2], new_size = regs[3];
        static uint32_t next_hrealloc = 0x01000000;
        uint8_t* old_host = mem.Translate(old_ptr);
        uint8_t* new_host = mem.Alloc(next_hrealloc, new_size);
        if (old_host && new_host) memcpy(new_host, old_host, new_size);
        regs[0] = next_hrealloc;
        next_hrealloc += (new_size + 0xFFF) & ~0xFFF;
        return true;
    });
    Thunk("HeapSize", 48, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0x1000; return true;
    });
    Thunk("HeapValidate", 51, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 1; return true;
    });
    /* Shared counter for malloc/calloc/realloc/new to prevent overlap */
    static uint32_t next_malloc = 0x01100000;
    Thunk("malloc", 1041, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t size = regs[0];
        uint32_t alloc_size = size > 0 ? size : 0x10;
        mem.Alloc(next_malloc, alloc_size);
        regs[0] = next_malloc;
        next_malloc += (alloc_size + 0xFFF) & ~0xFFF;
        return true;
    });
    Thunk("calloc", 1346, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t size = regs[0] * regs[1];
        uint32_t alloc_size = size > 0 ? size : 0x10;
        mem.Alloc(next_malloc, alloc_size);
        uint8_t* p = mem.Translate(next_malloc);
        if (p) memset(p, 0, size);
        regs[0] = next_malloc;
        next_malloc += (alloc_size + 0xFFF) & ~0xFFF;
        return true;
    });
    Thunk("new", 1095, thunk_handlers["malloc"]);
    Thunk("realloc", 1054, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t old_ptr = regs[0], size = regs[1];
        uint32_t alloc_size = size > 0 ? size : 0x10;
        uint8_t* new_host = mem.Alloc(next_malloc, alloc_size);
        uint8_t* old_host = old_ptr ? mem.Translate(old_ptr) : nullptr;
        if (old_host && new_host) memcpy(new_host, old_host, std::min(size, (uint32_t)0x1000));
        regs[0] = next_malloc;
        next_malloc += (alloc_size + 0xFFF) & ~0xFFF;
        return true;
    });
    Thunk("free", 1018, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0; return true;
    });
    Thunk("delete", 1094, thunk_handlers["free"]);
    Thunk("_msize", [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0x1000; return true;
    });
}
