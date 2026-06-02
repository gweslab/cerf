#include "jit_code_arena.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "../core/cerf_emulator.h"
#include "../core/log.h"

JitCodeArena::~JitCodeArena() {
    if (region_start_) {
        VirtualFree(region_start_, 0, MEM_RELEASE);
        region_start_ = nullptr;
    }
}

void JitCodeArena::Initialize() {
    region_start_ = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, kRegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!region_start_) {
        LOG(Caution, "JitCodeArena: VirtualAlloc(%zu) failed gle=%lu\n",
            kRegionSize, GetLastError());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    cursor_      = region_start_;
    region_end_  = region_start_ + kRegionSize;
    region_size_ = kRegionSize;
}

uint8_t* JitCodeArena::Allocate(size_t size) {
    if (cursor_ + size > region_end_) return nullptr;
    uint8_t* address = cursor_;
    cursor_ += size;
    return address;
}

void JitCodeArena::FreeUnusedTail(uint8_t* start_of_free) {
    uint8_t* aligned = reinterpret_cast<uint8_t*>(
        (reinterpret_cast<uintptr_t>(start_of_free) + 3u) &
        ~static_cast<uintptr_t>(3u));
    if (aligned != start_of_free) {
        aligned[-1] = 0x90;
    }
    cursor_ = aligned;
}

void JitCodeArena::Flush() {
    cursor_ = region_start_;
}
