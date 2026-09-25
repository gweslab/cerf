#pragma once

#include "../core/service.h"

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <mutex>

class StateWriter;
class StateReader;

class EmulatedMemory : public Service {
public:
    using Service::Service;

    void OnReady() override;

    static constexpr uint32_t PAGE_SIZE = 0x1000;

    static constexpr size_t kMaxRegions = 64;

    /* `decode_span` (0 = `size`) is the address space the chip select decodes onto
       this region. A span wider than `size` repeats the region through the window,
       which requires a power-of-two `size` dividing the span. */
    void AddRegion(uint32_t base, uint32_t size,
                   DWORD page_protect = PAGE_READWRITE,
                   uint32_t decode_span = 0);

    uint8_t* Translate(uint32_t vaddr);

    uint8_t* TryTranslate(uint32_t paddr);

    /* TryTranslateWrite returns nullptr for PAGE_READONLY /
       PAGE_EXECUTE_READ regions so writes dispatch as MMIO. */
    uint8_t* TryTranslateWrite(uint32_t paddr);

    uint8_t* TryTranslateRange(uint64_t paddr, uint64_t size, bool write = false);

    bool IsSlotRangeUniform(uint32_t span_bytes, uint32_t pa);

    uint8_t  ReadByte(uint32_t vaddr);
    uint16_t ReadHalf(uint32_t vaddr);
    uint32_t ReadWord(uint32_t vaddr);
    uint64_t ReadDword(uint32_t vaddr);
    void     WriteByte(uint32_t vaddr, uint8_t  value);
    void     WriteHalf(uint32_t vaddr, uint16_t value);
    void     WriteWord(uint32_t vaddr, uint32_t value);
    void     WriteDword(uint32_t vaddr, uint64_t value);

    /* Bulk copy from host buffer into emulated memory at vaddr. The
       entire range must fall inside one declared region; halts on
       unmapped destination or boundary-crossing copy. */
    void CopyIn(uint32_t vaddr, const void* host_src, size_t size);

    /* Bulk copy out of emulated memory. Same one-region contract as
       CopyIn. */
    void CopyOut(uint32_t vaddr, void* host_dst, size_t size);

    bool CanCopyRange(uint32_t paddr, size_t size, bool writable);

    /* Power-cycle RAM loss: zero every backed volatile region. Flash
       (PAGE_READONLY / PAGE_EXECUTE_READ) keeps its contents - guest NOR
       writes survive a real power cycle. JIT thread at reset delivery
       only; anywhere else the memset races guest stores. */
    void WipeVolatileRegions();

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);

    void SaveFlashRegions(StateWriter& w);
    void RestoreFlashRegions(StateReader& r);

    /* Total bytes across volatile regions - the save-progress denominator. */
    uint64_t VolatileByteCount() const;

private:
    struct Region {
        uint32_t              base         = 0;
        uint32_t              size         = 0;   /* backed bytes */
        uint32_t              span         = 0;
        uint32_t              wrap_mask    = 0xFFFFFFFFu;
        DWORD                 page_protect = 0;
        std::atomic<uint8_t*> host_ptr{nullptr};  /* lazy first-touch */
    };

    /* Lock-free read: load_acquire count_, linear scan regions_[0..n). */
    Region*  FindRegion(uint32_t vaddr);
    /* Shared CopyIn/CopyOut gate: region containing [vaddr, vaddr+size)
       or fatal (unmapped / boundary-crossing). */
    Region*  BulkRegionFor(uint32_t vaddr, size_t size, const char* op);
    Region*  BulkRegion(uint32_t vaddr, size_t size);
    static bool IsFlash(const Region& r);
    uint32_t RegionCount(bool flash) const;
    void     SaveRegions(StateWriter& w, bool flash);
    void     RestoreRegions(StateReader& r, bool flash);
    /* Atomic first-touch CAS on host_ptr. Halts on VirtualAlloc fail. */
    uint8_t* EnsureBacked(Region* r);

    Region              regions_[kMaxRegions]{};
    std::atomic<size_t> count_{0};
    std::mutex          add_mutex_;
};
