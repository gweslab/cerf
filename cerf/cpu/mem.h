#pragma once
#include <windows.h>
#include <cstdint>
#include <map>
#include <vector>
#include <cstring>
#include <cstdio>
#include <mutex>

/* Emulated memory manager for ARM address space.
   Uses VirtualAlloc on the host to back emulated memory regions. */

struct MemRegion {
    uint32_t base;
    uint32_t size;
    uint8_t* host_ptr;   /* Host-side allocation */
    DWORD    protect;
    bool     is_stack;
    bool     is_external = false; /* True for externally-owned buffers (don't free) */
};

class EmulatedMemory {
public:
    static const uint32_t PAGE_SIZE = 0x1000;
    static const uint32_t STACK_SIZE = 1024 * 1024; /* 1 MB stack */
    static const uint32_t STACK_BASE = 0x01000000;  /* Stack grows down from here (above 64KB boundary) */

    /* Per-thread KData page redirect. When set, reads/writes to 0xFFFFC000-0xFFFFCFFF
       go to this buffer instead of shared memory. Each ARM thread sets this to its
       own ThreadContext::kdata[] before entering ARM execution. */
    static thread_local uint8_t* kdata_override;

    std::vector<MemRegion> regions;
    std::mutex alloc_mutex;  /* Protects regions vector during Alloc/Reserve */

    ~EmulatedMemory() {
        for (auto& r : regions) {
            if (r.host_ptr && !r.is_external)
                VirtualFree(r.host_ptr, 0, MEM_RELEASE);
        }
    }

    /* Allocate a region in the emulated address space.
       Identity-maps ARM addresses to host addresses so ARM pointers are valid
       native pointers — needed when ARM code passes struct pointers to native
       Win32 controls (e.g. tab control messages via SendMessageW). */
    /* Pre-reserve a large address range for identity-mapped allocations.
       Subsequent Alloc() calls within this range will MEM_COMMIT pages
       without needing 64KB-aligned MEM_RESERVE (which fails for non-aligned pages). */
    bool Reserve(uint32_t base, uint32_t size) {
        std::lock_guard<std::mutex> lock(alloc_mutex);
        size = AlignUp(size, PAGE_SIZE);
        LPVOID rv = VirtualAlloc((LPVOID)(uintptr_t)base, size, MEM_RESERVE, PAGE_READWRITE);
        if (!rv) {
            fprintf(stderr, "[MEM] Reserve 0x%08X+0x%X failed (err=%lu)\n", base, size, GetLastError());
            return false;
        }
        return true;
    }

    uint8_t* Alloc(uint32_t base, uint32_t size, DWORD protect = PAGE_READWRITE, bool is_stack = false) {
        std::lock_guard<std::mutex> lock(alloc_mutex);
        size = AlignUp(size, PAGE_SIZE);
        /* Try to allocate at the exact ARM address for identity mapping */
        uint8_t* ptr = nullptr;
        if (base >= 0x10000) { /* Addresses below 64KB can't be allocated on Windows */
            /* First try MEM_COMMIT only (works if address is within a pre-reserved range) */
            ptr = (uint8_t*)VirtualAlloc((LPVOID)(uintptr_t)base, size,
                                         MEM_COMMIT, PAGE_READWRITE);
            if (!ptr) {
                /* Not within a reservation — try full MEM_COMMIT | MEM_RESERVE
                   (only succeeds at 64KB-aligned addresses) */
                ptr = (uint8_t*)VirtualAlloc((LPVOID)(uintptr_t)base, size,
                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            }
        }
        if (!ptr) {
            /* Fall back to arbitrary address if identity mapping fails */
            ptr = (uint8_t*)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (ptr)
                fprintf(stderr, "[MEM] Region 0x%08X+0x%X: fallback to host %p (NOT identity-mapped)\n", base, size, ptr);
        }
        if (!ptr) {
            fprintf(stderr, "[MEM] Failed to allocate 0x%X bytes for region 0x%08X\n", size, base);
            return nullptr;
        }
        memset(ptr, 0, size);
        regions.push_back({ base, size, ptr, protect, is_stack });
        return ptr;
    }

    /* Find the host pointer for an emulated address */
    uint8_t* Translate(uint32_t addr) const {
        /* Per-thread KData page: each thread has its own TLS slots and thread ID.
           Single branch, almost always not-taken (well-predicted). */
        if (kdata_override && (addr >> 12) == 0xFFFFC)
            return kdata_override + (addr & 0xFFF);
        for (auto& r : regions) {
            if (addr >= r.base && addr < r.base + r.size) {
                return r.host_ptr + (addr - r.base);
            }
        }
        return nullptr;
    }

    bool IsValid(uint32_t addr) const {
        return Translate(addr) != nullptr;
    }

    uint8_t Read8(uint32_t addr) const {
        uint8_t* p = Translate(addr);
        if (!p) {
            p = const_cast<EmulatedMemory*>(this)->AutoAlloc(addr);
            if (p) return p[addr & (PAGE_SIZE - 1)];
            LogFault("Read8", addr); return 0;
        }
        return *p;
    }

    uint16_t Read16(uint32_t addr) const {
        uint8_t* p = Translate(addr);
        if (!p) {
            p = const_cast<EmulatedMemory*>(this)->AutoAlloc(addr);
            if (p) return *(uint16_t*)(p + (addr & (PAGE_SIZE - 1)));
            LogFault("Read16", addr); return 0;
        }
        return *(uint16_t*)p;
    }

    uint32_t Read32(uint32_t addr) const {
        uint8_t* p = Translate(addr);
        if (!p) {
            p = const_cast<EmulatedMemory*>(this)->AutoAlloc(addr);
            if (p) { p += (addr & (PAGE_SIZE - 1)); return *(uint32_t*)p; }
            LogFault("Read32", addr); return 0;
        }
        return *(uint32_t*)p;
    }

    void Write8(uint32_t addr, uint8_t val) {
        uint8_t* p = Translate(addr);
        if (!p) {
            p = AutoAlloc(addr);
            if (p) { p[addr & (PAGE_SIZE - 1)] = val; return; }
            LogFault("Write8", addr); return;
        }
        *p = val;
    }

    void Write16(uint32_t addr, uint16_t val) {
        uint8_t* p = Translate(addr);
        if (!p) {
            p = AutoAlloc(addr);
            if (p) { *(uint16_t*)(p + (addr & (PAGE_SIZE - 1))) = val; return; }
            LogFault("Write16", addr); return;
        }
        *(uint16_t*)p = val;
    }

    void Write32(uint32_t addr, uint32_t val) {
        uint8_t* p = Translate(addr);
        if (!p) {
            p = AutoAlloc(addr);
            if (p) { *(uint32_t*)(p + (addr & (PAGE_SIZE - 1))) = val; return; }
            LogFault("Write32", addr); return;
        }
        *(uint32_t*)p = val;
    }

    void WriteBytes(uint32_t addr, const void* src, uint32_t len) {
        uint8_t* p = Translate(addr);
        if (!p) { fprintf(stderr, "[MEM] WriteBytes fault at 0x%08X len=0x%X\n", addr, len); return; }
        memcpy(p, src, len);
    }

    /* Register an externally-owned buffer as an emulated region.
       The caller retains ownership; the buffer must outlive the mapping.
       Used for CreateDIBSection pvBits: maps native bitmap data into ARM space. */
    void AddExternalRegion(uint32_t base, uint32_t size, uint8_t* host_ptr) {
        MemRegion r = {};
        r.base = base; r.size = size; r.host_ptr = host_ptr;
        r.protect = PAGE_READWRITE; r.is_external = true;
        regions.push_back(r);
    }

    /* Remove a previously-added external region by its base address. */
    void RemoveExternalRegion(uint32_t base) {
        for (auto it = regions.begin(); it != regions.end(); ++it) {
            if (it->base == base) { regions.erase(it); return; }
        }
    }

    /* Allocate the stack region */
    uint32_t AllocStack() {
        uint32_t stack_bottom = STACK_BASE - STACK_SIZE;
        Alloc(stack_bottom, STACK_SIZE, PAGE_READWRITE, true);
        return STACK_BASE - 16; /* Return initial SP, slightly below top */
    }

    /* Auto-allocate on fault: if an access hits unmapped memory, allocate a page */
    uint8_t* AutoAlloc(uint32_t addr) {
        uint32_t page_base = addr & ~(PAGE_SIZE - 1);
        return Alloc(page_base, PAGE_SIZE);
    }

private:
    mutable int fault_count = 0;

    void LogFault(const char* op, uint32_t addr) const {
        if (fault_count < 10) {
            fprintf(stderr, "[MEM] %s fault at 0x%08X\n", op, addr);
        } else if (fault_count == 10) {
            fprintf(stderr, "[MEM] ... suppressing further fault messages\n");
        }
        fault_count++;
    }

    static uint32_t AlignUp(uint32_t val, uint32_t align) {
        return (val + align - 1) & ~(align - 1);
    }
};
