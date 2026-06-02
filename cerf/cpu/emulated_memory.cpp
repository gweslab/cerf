#include "emulated_memory.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "../boards/page_table_builder.h"

#include <cstring>

REGISTER_SERVICE(EmulatedMemory);

void EmulatedMemory::OnReady() {
    auto& page = emu_.Get<PageTableBuilder>();
    for (const auto& r : page.BackedMemoryRegions()) {
        AddRegion(r.pa_base, r.size, r.page_protect);
    }
}

void EmulatedMemory::AddRegion(uint32_t base, uint32_t size,
                               DWORD page_protect) {
    std::lock_guard<std::mutex> lk(add_mutex_);

    /* count_.load(acquire) inside the writer lock — we hold the writer
       lock, so no other writer can be racing; the acquire pairs with
       earlier store_release publications. */
    const size_t n = count_.load(std::memory_order_acquire);

    for (size_t i = 0; i < n; ++i) {
        const Region& r = regions_[i];
        if (base < r.base + r.size && r.base < base + size) {
            LOG(Caution, "EmulatedMemory::AddRegion overlap: new "
                    "[0x%08X..0x%08X) vs existing [0x%08X..0x%08X)\n",
                    base, base + size, r.base, r.base + r.size);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
    }

    if (n >= kMaxRegions) {
        LOG(Caution, "EmulatedMemory::AddRegion: kMaxRegions=%zu exceeded "
                "(new [0x%08X..0x%08X)). Bump kMaxRegions in "
                "emulated_memory.h.\n",
                kMaxRegions, base, base + size);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    regions_[n].base         = base;
    regions_[n].size         = size;
    regions_[n].page_protect = page_protect;

    count_.store(n + 1, std::memory_order_release);

    LOG(Mem, "AddRegion 0x%08X size 0x%X protect 0x%X (slot %zu)\n",
        base, size, page_protect, n);
}

EmulatedMemory::Region* EmulatedMemory::FindRegion(uint32_t vaddr) {
    const size_t n = count_.load(std::memory_order_acquire);
    for (size_t i = 0; i < n; ++i) {
        Region& r = regions_[i];
        if (vaddr >= r.base && vaddr < r.base + r.size) {
            return &r;
        }
    }
    return nullptr;
}

uint8_t* EmulatedMemory::EnsureBacked(Region* r) {
    /* Fast path — already backed. memory_order_acquire so reads of the
       host page that follow this load see the VirtualAlloc memory. */
    if (uint8_t* ptr = r->host_ptr.load(std::memory_order_acquire)) {
        return ptr;
    }

    uint8_t* allocated = static_cast<uint8_t*>(::VirtualAlloc(
        nullptr, r->size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!allocated) {
        LOG(Caution, "EmulatedMemory::EnsureBacked VirtualAlloc failed "
                "region 0x%08X size 0x%X (GLE=%lu)\n",
                r->base, r->size, ::GetLastError());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    uint8_t* expected = nullptr;
    if (r->host_ptr.compare_exchange_strong(
            expected, allocated,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        LOG(Mem, "Region 0x%08X backed at host %p\n", r->base, allocated);
        return allocated;
    }

    /* Lost the race. expected now holds the winner's pointer. Free
       our orphan allocation and return the winner. */
    ::VirtualFree(allocated, 0, MEM_RELEASE);
    return expected;
}

uint8_t* EmulatedMemory::Translate(uint32_t vaddr) {
    Region* r = FindRegion(vaddr);
    if (!r) {
        LOG(Caution, "EmulatedMemory::Translate unmapped 0x%08X\n", vaddr);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    return EnsureBacked(r) + (vaddr - r->base);
}

uint8_t* EmulatedMemory::TryTranslate(uint32_t paddr) {
    Region* r = FindRegion(paddr);
    if (!r) return nullptr;
    return EnsureBacked(r) + (paddr - r->base);
}

uint8_t* EmulatedMemory::TryTranslateWrite(uint32_t paddr) {
    Region* r = FindRegion(paddr);
    if (!r) {
        return nullptr;
    }

    /* PAGE_READONLY / PAGE_EXECUTE_READ → flash / ROM region. Write
       must dispatch to the flash controller / I/O peripheral instead
       of caching a host pointer; signal that to the walker by
       returning nullptr. */
    if (r->page_protect == PAGE_READONLY ||
        r->page_protect == PAGE_EXECUTE_READ) {
        return nullptr;
    }

    return EnsureBacked(r) + (paddr - r->base);
}

bool EmulatedMemory::IsSlotRangeUniform(uint32_t pte, uint32_t pa) {
    uint32_t gran;
    switch (pte & 3u) {
        case 0:  gran = 0x100000u; break;  /* section, 1 MB */
        case 1:  gran = 0x10000u;  break;  /* large page, 64 KB */
        default: return true;              /* small / ext-small <= 4 KB: one region */
    }
    const uint32_t base = pa & ~(gran - 1u);
    Region* r = FindRegion(base);
    if (!r) return true;  /* base not RAM-backed: host_adjust is 0 regardless. */
    return base >= r->base &&
           static_cast<uint64_t>(base) + gran <=
               static_cast<uint64_t>(r->base) + r->size;
}

uint8_t EmulatedMemory::ReadByte(uint32_t vaddr) {
    return *Translate(vaddr);
}

uint16_t EmulatedMemory::ReadHalf(uint32_t vaddr) {
    uint16_t v;
    std::memcpy(&v, Translate(vaddr), sizeof(v));
    return v;
}

uint32_t EmulatedMemory::ReadWord(uint32_t vaddr) {
    uint32_t v;
    std::memcpy(&v, Translate(vaddr), sizeof(v));
    return v;
}

uint64_t EmulatedMemory::ReadDword(uint32_t vaddr) {
    uint64_t v;
    std::memcpy(&v, Translate(vaddr), sizeof(v));
    return v;
}

void EmulatedMemory::WriteByte(uint32_t vaddr, uint8_t value) {
    *Translate(vaddr) = value;
}

void EmulatedMemory::WriteHalf(uint32_t vaddr, uint16_t value) {
    std::memcpy(Translate(vaddr), &value, sizeof(value));
}

void EmulatedMemory::WriteWord(uint32_t vaddr, uint32_t value) {
    std::memcpy(Translate(vaddr), &value, sizeof(value));
}

void EmulatedMemory::WriteDword(uint32_t vaddr, uint64_t value) {
    std::memcpy(Translate(vaddr), &value, sizeof(value));
}

void EmulatedMemory::CopyIn(uint32_t vaddr, const void* host_src, size_t size) {
    Region* r = FindRegion(vaddr);
    if (!r) {
        LOG(Caution, "EmulatedMemory::CopyIn unmapped destination "
                "0x%08X size 0x%zX\n", vaddr, size);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    uint64_t end = static_cast<uint64_t>(vaddr) + size;
    if (end > static_cast<uint64_t>(r->base) + r->size) {
        LOG(Caution, "EmulatedMemory::CopyIn crosses region boundary at "
                "0x%08X size 0x%zX (region 0x%08X size 0x%X)\n",
                vaddr, size, r->base, r->size);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    uint8_t* host = EnsureBacked(r);
    std::memcpy(host + (vaddr - r->base), host_src, size);
}
