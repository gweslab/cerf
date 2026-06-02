#pragma once

#include "../core/service.h"

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <mutex>

class EmulatedMemory : public Service {
public:
    using Service::Service;

    void OnReady() override;

    static constexpr uint32_t PAGE_SIZE = 0x1000;

    static constexpr size_t kMaxRegions = 64;

    void AddRegion(uint32_t base, uint32_t size,
                   DWORD page_protect = PAGE_READWRITE);

    uint8_t* Translate(uint32_t vaddr);

    uint8_t* TryTranslate(uint32_t paddr);

    /* TryTranslateWrite returns nullptr for PAGE_READONLY /
       PAGE_EXECUTE_READ regions so writes dispatch as MMIO. */
    uint8_t* TryTranslateWrite(uint32_t paddr);

    /* True iff the slot-granularity range containing `pa` lies entirely within
       one backed region (a single host_adjust is valid for the whole TLB slot).
       Section/large slots straddling a region boundary or peripheral hole
       return false so the MMU routes them per access. pte[1:0] = granularity. */
    bool IsSlotRangeUniform(uint32_t pte, uint32_t pa);

    uint8_t  ReadByte(uint32_t vaddr);
    uint16_t ReadHalf(uint32_t vaddr);
    uint32_t ReadWord(uint32_t vaddr);
    uint64_t ReadDword(uint32_t vaddr);
    void     WriteByte(uint32_t vaddr, uint8_t  value);
    void     WriteHalf(uint32_t vaddr, uint16_t value);
    void     WriteWord(uint32_t vaddr, uint32_t value);
    void     WriteDword(uint32_t vaddr, uint64_t value);

    /* Bulk copy from host buffer into emulated memory at vaddr.
       The entire range must fall inside one declared region. Halts
       on unmapped destination or boundary-crossing copy. Used to
       load PE images into the emulated address space. */
    void CopyIn(uint32_t vaddr, const void* host_src, size_t size);

private:
    struct Region {
        uint32_t              base         = 0;
        uint32_t              size         = 0;
        DWORD                 page_protect = 0;
        std::atomic<uint8_t*> host_ptr{nullptr};  /* lazy first-touch */
    };

    /* Lock-free read: load_acquire count_, linear scan regions_[0..n). */
    Region*  FindRegion(uint32_t vaddr);
    /* Atomic first-touch CAS on host_ptr. Halts on VirtualAlloc fail. */
    uint8_t* EnsureBacked(Region* r);

    Region              regions_[kMaxRegions]{};
    std::atomic<size_t> count_{0};
    std::mutex          add_mutex_;
};
