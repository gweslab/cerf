#pragma once

#include <cstdint>

#include "../../core/service.h"
#include "mips_cpu_state.h"

struct IsaBlockSpace;
class StateWriter;
class StateReader;

namespace MipsSeg {
    constexpr uint32_t kKusegEnd     = 0x80000000;  /* kuseg  0x00000000..0x7FFFFFFF, TLB-mapped */
    constexpr uint32_t kKseg1Base    = 0xA0000000;  /* kseg0  ..0x9FFFFFFF, unmapped cached */
    constexpr uint32_t kKseg2Base    = 0xC0000000;  /* kseg1  ..0xBFFFFFFF, unmapped uncached */
    constexpr uint32_t kUnmappedMask = 0x1FFFFFFF;  /* kseg0/1 VA -> PA */

    constexpr bool IsUnmapped(uint32_t va) {
        return va >= kKusegEnd && va < kKseg2Base;
    }
    constexpr uint32_t UnmappedPa(uint32_t va) { return va & kUnmappedMask; }
}

/* EntryLo0/1 bit layout (R4000), per QEMU tlb_helper.c r4k_fill_tlb. */
namespace MipsEntryLo {
    constexpr uint32_t kGlobal = 1u << 0;   /* G - matches any ASID (set in both halves) */
    constexpr uint32_t kValid  = 1u << 1;   /* V */
    constexpr uint32_t kDirty  = 1u << 2;   /* D - writable */
}

/* Outcome of a translation attempt; a non-MATCH result is delivered to the
   guest as the corresponding CP0 exception (refill / invalid / modified). */
enum class MipsTlbResult {
    kMatch,     /* pa valid (TLBRET_MATCH) */
    kNoMatch,   /* TLB miss   -> TLB-refill   (TLBRET_NOMATCH) */
    kInvalid,   /* entry V=0  -> TLB-invalid  (TLBRET_INVALID) */
    kModified,  /* store, D=0 -> TLB-modified (TLBRET_DIRTY) */
};

enum class MipsAccess { kFetch, kRead, kWrite };

class MipsMmu : public Service {
public:
    using Service::Service;

    void Bind(IsaBlockSpace* b32, IsaBlockSpace* b16) {
        blocks32_ = b32;
        blocks16_ = b16;
    }

    /* Translate a guest VA. kseg0/kseg1 resolve directly; kuseg/kseg2 walk the
       software TLB (ASID from CP0_EntryHi). On kMatch, *pa holds the physical
       address; otherwise the caller raises the indicated CP0 exception. */
    MipsTlbResult Translate(MipsCpuState* st, uint32_t va, MipsAccess acc,
                            uint32_t* pa) {
        if (injection_band_size_ != 0u &&
            va - injection_band_va_ < injection_band_size_) {
            *pa = injection_band_pa_ + (va - injection_band_va_);
            return MipsTlbResult::kMatch;
        }
        if (MipsSeg::IsUnmapped(va)) {
            *pa = MipsSeg::UnmappedPa(va);
            return MipsTlbResult::kMatch;
        }
        return MapAddress(st, va, acc, pa);
    }

    /* True iff va's page is global (kseg0/kseg1, or a TLB entry with G=1). The
       JIT routes a global page's block to the shared `global` index, else to
       per_asid[EntryHi.ASID]. */
    bool ExecPageGlobal(MipsCpuState* st, uint32_t va) {
        if (MipsSeg::IsUnmapped(va)) {
            return true;
        }
        return MappedPageGlobal(st, va);
    }

    /* CP0 TLB instructions. */
    virtual void WriteIndexed(MipsCpuState* st) = 0;   /* tlbwi */
    virtual void WriteRandom (MipsCpuState* st) = 0;   /* tlbwr */
    virtual void Probe       (MipsCpuState* st) = 0;   /* tlbp  */
    virtual void Read        (MipsCpuState* st) = 0;   /* tlbr  */

    virtual uint32_t RandomIndex(MipsCpuState* st) = 0;

    /* cpu_mips_tlb_flush: drop the whole jump cache + discard all shadow
       entries (tlb_helper.c:492). Called on a CP0 ASID change. */
    void FlushAll(MipsCpuState* st);

    void SetInjectionBand(uint32_t va, uint32_t pa, uint32_t size) {
        injection_band_va_   = va;
        injection_band_pa_   = pa;
        injection_band_size_ = size;
    }

    /* Hibernation: the TLB array lives in MipsCpuState (saved with the CPU
       blob); this serializes the tlbwr replacement-index RNG state. */
    void SaveState(StateWriter& w) const;
    void RestoreState(StateReader& r);

protected:
    /* The mapped-segment TLB walk (QEMU CPUMIPSTLBContext::map_address). */
    virtual MipsTlbResult MapAddress(MipsCpuState* st, uint32_t va, MipsAccess acc,
                                     uint32_t* pa) = 0;

    virtual bool MappedPageGlobal(MipsCpuState* st, uint32_t va) = 0;

    /* cpu_mips_get_random (cp0_helper.c:204): an LCG over [first, first+nb),
       never returning the previous index. Never below `first` - a software
       refill uses mfc0 Random as its tlbwi index, so a lower value lands a
       mapping in a reserved slot tlbwr can never evict. */
    uint32_t NextRandom(uint32_t first, uint32_t nb);

    /* QEMU tb_jmp_cache_clear_page (accel/tcg/cputlb.c:157), on both ISA spaces. */
    void JumpCacheClearPage(uint32_t page_va);

private:
    IsaBlockSpace* blocks32_ = nullptr;
    IsaBlockSpace* blocks16_ = nullptr;
    uint32_t lcg_seed_        = 1;
    uint32_t prev_random_idx_ = 0;
    uint32_t injection_band_va_   = 0;
    uint32_t injection_band_pa_   = 0;
    uint32_t injection_band_size_ = 0;
};
