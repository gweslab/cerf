#include "arm_tlb_ops.h"

#include <bit>
#include <cstring>

void ArmTlbFlushAll(ArmTlbUnit* unit) {
    /* tag == kArmTlbInvalidTag has low bits set, so it can never equal a
       page-aligned folded-VA tag - 0xFF-filling marks every entry empty. */
    std::memset(unit->entries, 0xFF, sizeof(unit->entries));
    ArmTlbSpanTracker* tracker = unit->span_tracker;
    if (!tracker) return;
    for (uint16_t region : tracker->active_regions) {
        tracker->region_refs[region] = 0u;
        tracker->active_region_bits[region >> 5] &= ~(1u << (region & 31u));
    }
    tracker->active_regions.clear();
    std::memset(tracker->entry_bits, 0, sizeof(tracker->entry_bits));
}

namespace {

void SetLargeSpanSlot(ArmTlbUnit* unit, uint32_t slot, bool large) {
    ArmTlbSpanTracker* tracker = unit->span_tracker;
    if (!tracker) return;
    const uint32_t mask = 1u << (slot & 31u);
    uint32_t& bits = tracker->entry_bits[slot >> 5];
    if (large)
        bits |= mask;
    else
        bits &= ~mask;
}

void TrackLargeSpan(ArmTlbUnit* unit, uint32_t slot, bool add) {
    const ArmTlbEntry& entry = unit->entries[slot];
    const bool large = entry.tag != kArmTlbInvalidTag && entry.span_shift > 12u;
    if (!large) {
        SetLargeSpanSlot(unit, slot, false);
        return;
    }
    ArmTlbSpanTracker* tracker = unit->span_tracker;
    if (!tracker) return;
    const uint32_t span_bytes = 1u << entry.span_shift;
    const uint32_t page = entry.tag & ~kArmTlbIoTagBit;
    const uint32_t first = (page & ~(span_bytes - 1u)) >> kArmSectionShift;
    const uint32_t last = ((page & ~(span_bytes - 1u)) + span_bytes - 1u) >>
                          kArmSectionShift;
    const uint32_t count = last - first + 1u;
    for (uint32_t i = 0; i < count; ++i) {
        const uint32_t region = first + i;
        uint16_t& refs = tracker->region_refs[region];
        if (add) {
            if (refs == 0u) {
                const uint32_t mask = 1u << (region & 31u);
                uint32_t& active = tracker->active_region_bits[region >> 5];
                if ((active & mask) == 0u) {
                    active |= mask;
                    tracker->active_regions.push_back(static_cast<uint16_t>(region));
                }
            }
            ++refs;
        } else {
            --refs;
        }
    }
    SetLargeSpanSlot(unit, slot, add);
}

ArmTlbEntry& PrepareInsert(ArmTlbUnit* unit, uint32_t base) {
    TrackLargeSpan(unit, base + kArmTlbWays - 1u, false);
    ArmTlbEntry& entry = ArmTlbInsertSlot(unit, base);
    if (unit->span_tracker) {
        for (uint32_t w = 0; w < kArmTlbWays; ++w) {
            const ArmTlbEntry& shifted = unit->entries[base + w];
            SetLargeSpanSlot(unit, base + w,
                             shifted.tag != kArmTlbInvalidTag &&
                             shifted.span_shift > 12u);
        }
    }
    return entry;
}

}

ArmTlbInvalidation ArmTlbInvalidateByVa(ArmTlbUnit* unit,
                                        uint32_t process_id, uint32_t va) {
    va = ArmFcseFold(va, process_id);
    const uint32_t page = va & 0xFFFFF000u;
    const uint32_t base = ArmTlbSetBase(va);
    uint32_t span_shift = 12u;

    /* ARM DDI 0406C.d B3.10.1. */
    ArmTlbSpanTracker* tracker = unit->span_tracker;
    if (!tracker || tracker->region_refs[page >> kArmSectionShift] == 0u) {
        for (uint32_t w = 0; w < kArmTlbWays; ++w) {
            ArmTlbEntry& entry = unit->entries[base + w];
            if ((entry.tag & ~kArmTlbIoTagBit) == page) {
                entry.tag = kArmTlbInvalidTag;
            }
        }
    } else {
        for (uint32_t word = 0; word < kArmTlbSpanBitWords; ++word) {
            uint32_t bits = tracker->entry_bits[word];
            while (bits != 0u) {
                const uint32_t bit = std::countr_zero(bits);
                const uint32_t slot = (word << 5) + bit;
                ArmTlbEntry& entry = unit->entries[slot];
                const uint32_t entry_page = entry.tag & ~kArmTlbIoTagBit;
                const uint32_t entry_span = 1u << entry.span_shift;
                const uint32_t entry_mask = ~(entry_span - 1u);
                if ((entry_page & entry_mask) == (page & entry_mask)) {
                    if (entry.span_shift > span_shift) span_shift = entry.span_shift;
                    TrackLargeSpan(unit, slot, false);
                    entry.tag = kArmTlbInvalidTag;
                }
                bits &= bits - 1u;
            }
        }
        for (uint32_t w = 0; w < kArmTlbWays; ++w) {
            ArmTlbEntry& entry = unit->entries[base + w];
            if (entry.span_shift <= 12u &&
                (entry.tag & ~kArmTlbIoTagBit) == page) {
                entry.tag = kArmTlbInvalidTag;
            }
        }
    }
    const uint32_t span_bytes = 1u << span_shift;
    const uint32_t span_mask = ~(span_bytes - 1u);
    return {page & span_mask, span_bytes};
}

/* Install a direct-mapped fast-path entry for a uniform RAM page. host
   corresponds to folded_va's PA, so va_addend = host - folded_va reconstructs
   the host pointer for any access in the page (the page offset cancels). */
void FillFastTlb(ArmTlbUnit* unit, uint32_t folded_va, uint8_t* host,
                 uint32_t pa, uint8_t asid, bool global, bool writable,
                 uint32_t span_bytes) {
    const uint32_t base = ArmTlbSetBase(folded_va);
    const uint32_t page = folded_va & 0xFFFFF000u;
    /* Reuse an existing way for the same page (e.g. a read-only entry being
       upgraded to writable) so a re-walk doesn't leave a stale duplicate;
       otherwise take a fresh way-0 slot, evicting the set's LRU way. */
    ArmTlbEntry* e = nullptr;
    for (uint32_t w = 0; w < kArmTlbWays; ++w) {
        ArmTlbEntry& c = unit->entries[base + w];
        if (c.tag == page && c.asid == asid &&
            c.global == (global ? 1u : 0u)) {
            TrackLargeSpan(unit, base + w, false);
            ArmTlbPromote(unit, base, static_cast<int>(w));
            e = &unit->entries[base];
            break;
        }
    }
    if (!e) e = &PrepareInsert(unit, base);
    e->tag       = page;
    e->va_addend = static_cast<uint32_t>(
        reinterpret_cast<uintptr_t>(host) - folded_va);
    e->pa_page   = pa & 0xFFFFF000u;
    e->asid      = asid;
    e->global    = global ? 1u : 0u;
    e->writable  = writable ? 1u : 0u;
    e->span_shift = static_cast<uint8_t>(std::countr_zero(span_bytes));
    TrackLargeSpan(unit, base, true);
}

/* I/O analog of FillFastTlb: a device page has no host pointer, so the entry
   records its PA tagged kArmTlbIoTagBit. ArmTlbMatchIoWay later resolves it via
   SetIoPending with no walk; writable mirrors the RAM read-only-upgrade rule. */
void FillFastTlbIo(ArmTlbUnit* unit, uint32_t folded_va, uint32_t pa,
                   uint8_t asid, bool global, bool writable,
                   uint32_t span_bytes) {
    const uint32_t base   = ArmTlbSetBase(folded_va);
    const uint32_t io_tag = (folded_va & 0xFFFFF000u) | kArmTlbIoTagBit;
    ArmTlbEntry* e = nullptr;
    for (uint32_t w = 0; w < kArmTlbWays; ++w) {
        ArmTlbEntry& c = unit->entries[base + w];
        if (c.tag == io_tag && c.asid == asid &&
            c.global == (global ? 1u : 0u)) {
            TrackLargeSpan(unit, base + w, false);
            ArmTlbPromote(unit, base, static_cast<int>(w));
            e = &unit->entries[base];
            break;
        }
    }
    if (!e) e = &PrepareInsert(unit, base);
    e->tag       = io_tag;
    e->va_addend = 0;
    e->pa_page   = pa & 0xFFFFF000u;
    e->asid      = asid;
    e->global    = global ? 1u : 0u;
    e->writable  = writable ? 1u : 0u;
    e->span_shift = static_cast<uint8_t>(std::countr_zero(span_bytes));
    TrackLargeSpan(unit, base, true);
}
