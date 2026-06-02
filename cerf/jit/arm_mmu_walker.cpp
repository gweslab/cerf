#include "arm_mmu.h"

#include "../core/log.h"
#include "../cpu/arm_processor_config.h"
#include "../cpu/emulated_memory.h"
#include "arm_mmu_ap_permits.h"
#include "arm_pte.h"

namespace {

/* Exec marks the 4-byte PA word(s) holding the fetched insn; a write to a
   marked word sets its page's dirty bit. Both gated to the DRAM word-bitmap
   extent; code outside DRAM is non-writable so cannot self-modify. kRead empty. */
template <ArmMmuAccess kAccess>
inline void NoteCodeTracking(ArmMmuState& st, uint32_t pa) {
    if (pa < st.code_word_base || pa >= st.code_word_top) return;
    const uint32_t off = pa - st.code_word_base;
    if constexpr (kAccess == ArmMmuAccess::kExecute) {
        /* A 32-bit Thumb-2 insn at a 2-aligned offset straddles two words;
           mark the words of its first and last byte or a write to the
           second-word half is missed and code goes stale. */
        const uint32_t w0 = off >> 2;
        const uint32_t w1 = (off + 3u) >> 2;
        st.code_xlat_bitmap[w0 >> 3] |= static_cast<uint8_t>(1u << (w0 & 7u));
        st.code_xlat_bitmap[w1 >> 3] |= static_cast<uint8_t>(1u << (w1 & 7u));
    } else if constexpr (kAccess == ArmMmuAccess::kWrite ||
                         kAccess == ArmMmuAccess::kReadWrite) {
        const uint32_t w = off >> 2;
        if (st.code_xlat_bitmap[w >> 3] & (1u << (w & 7u))) {
            const uint32_t page = off >> 12;
            st.code_page_dirty[page >> 3] |=
                static_cast<uint8_t>(1u << (page & 7u));
        }
    }
}

/* Install a direct-mapped fast-path entry for a uniform RAM page. host
   corresponds to folded_va's PA, so va_addend = host - folded_va reconstructs
   the host pointer for any access in the page (the page offset cancels). */
void FillFastTlb(ArmTlbUnit* unit, uint32_t folded_va, uint8_t* host,
                 uint32_t pa, uint8_t asid, bool global, bool writable) {
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
            ArmTlbPromote(unit, base, static_cast<int>(w));
            e = &unit->entries[base];
            break;
        }
    }
    if (!e) e = &ArmTlbInsertSlot(unit, base);
    e->tag       = page;
    e->va_addend = static_cast<uint32_t>(
        reinterpret_cast<uintptr_t>(host) - folded_va);
    e->pa_page   = pa & 0xFFFFF000u;
    e->asid      = asid;
    e->global    = global ? 1u : 0u;
    e->writable  = writable ? 1u : 0u;
}

}  // namespace

template <ArmMmuAccess kAccess>
uint8_t* ArmMmu::MapGuestVirtualToHost(ArmCpuState* cpu_state, uint32_t p) {
    constexpr bool kIsWrite = (kAccess == ArmMmuAccess::kWrite ||
                               kAccess == ArmMmuAccess::kReadWrite);
    io_pending_address_        = 0;
    io_pending_address_adjust_ = 0;

    /* ARM1136 TRM Table 3-44 §c1: SCTLR.XP=0 keeps legacy v5 subpage AP
       (4 APs in PTE bits[11:4]); XP=1 selects modern v6 format (APX|AP).
       Reset 0; the Keel BSP never sets it, so dropping the XP gate
       denies writes the kernel marked subpage-AP supervisor-RW. */
    const bool modern_v6_fmt = processor_config_->HasCp15V6() &&
                               state_.control_register.bits.xp;

    /* ARM1136 TRM Table 6-16: with XP=0 a coarse L2 type=3 is a 4 KB
       extended small page (base[31:12], single AP[5:4]); decoding it via
       the extended_small_page union (1 KB, base[31:10]) maps the wrong PA
       and the access re-faults forever. v5 cores keep the 1 KB decode. */
    const bool v6_ext_small = processor_config_->HasCp15V6() &&
                              !state_.control_register.bits.xp;

    if (!state_.control_register.bits.m) {
        uint8_t* host = memory_->TryTranslate(p);
        if (host) return host;
        SetIoPending(p);
        return nullptr;
    }

    /* FCSE fold: low-32-MB VAs are private to the current process. */
    if ((p & 0xFE000000u) == 0u) {
        p |= state_.process_id;
    }

    ArmTlbUnit* tlb_unit = (kAccess == ArmMmuAccess::kExecute)
        ? &state_.instruction_tlb
        : &state_.data_tlb;

    const bool is_user_mode = (cpu_state->cpsr.bits.mode == ArmMode::kUser);
    /* ARM DDI 0406C.c B3.9.1: ASID is CONTEXTIDR[7:0]. */
    const uint8_t current_asid = static_cast<uint8_t>(state_.contextidr & 0xFFu);

    /* DACR domain-0 = Manager(0b11) → AP attributes not checked (ARM
       DDI0406C B3 "Domains", p.B3-1362). All PTEs are domain 0 (walk
       faults non-zero domains); make this per-domain before mapping any
       non-zero domain or every domain inherits domain 0's setting. */
    const bool skip_ap = (state_.domain_access_control & 3u) == 3u;
    uint32_t effective_address = 0;

    /* Set-associative fast path: scan the set's ways for a live match (the
       inline JIT probe only checked way 0), promote a hit to way 0 (MRU) so the
       inline probe finds it next time, then resolve the host without a walk. A
       write to a page cached read-only falls through to the walk to re-check. */
    const uint32_t va_page  = p & 0xFFFFF000u;
    const uint32_t set_base = ArmTlbSetBase(p);
    const int hit_way =
        ArmTlbMatchWay(tlb_unit, set_base, va_page, current_asid, kIsWrite);
    if (hit_way >= 0) {
        ArmTlbPromote(tlb_unit, set_base, hit_way);
        const ArmTlbEntry& fast = tlb_unit->entries[set_base];
        const uint32_t pa = fast.pa_page | (p & 0x0FFFu);
        if constexpr (kAccess == ArmMmuAccess::kExecute) last_exec_pa_ = pa;
        NoteCodeTracking<kAccess>(state_, pa);
        return reinterpret_cast<uint8_t*>(
            static_cast<uintptr_t>(p) + fast.va_addend);
    }

    /* Fast-path miss — walk the in-RAM page table. */
    {
        const uint32_t ttbcr_n   = state_.ttbcr & 7u;
        const uint32_t ttbr0_mask = ~((1u << (14u - ttbcr_n)) - 1u);
        const bool use_ttbr1 = ttbcr_n != 0u &&
                               (p >> (32u - ttbcr_n)) != 0u;
        const uint32_t l1_base = use_ttbr1
            ? (state_.ttbr1 & 0xFFFFC000u)
            : (state_.translation_table_base.word & ttbr0_mask);
        const uint32_t l1_pa = l1_base | ((p >> 20) << 2);
        uint8_t* l1_host = memory_->TryTranslateWrite(l1_pa);
        if (!l1_host) {
            RaiseAbort(p, ArmFaultStatus::kExternalAbortTranslation1, kIsWrite);
            return nullptr;
        }
        ArmL1Pte l1_pte;
        l1_pte.word = *reinterpret_cast<uint32_t*>(l1_host);

        struct { uint32_t pte; bool global; } new_slot{};

        switch (l1_pte.fault.type) {
        case ArmL1PteType::kFault:
            RaiseAbort(p, ArmFaultStatus::kTranslationSection, kIsWrite);
            return nullptr;

        case ArmL1PteType::kCoarse: {
            if (l1_pte.coarse.domain != 0u) {
                RaiseAbort(p, ArmFaultStatus::kDomainPage, kIsWrite);
                return nullptr;
            }
            const uint32_t l2_pa = (l1_pte.coarse.page_table_base << 10) | (((p >> 12) & 0xFFu) << 2);
            uint8_t* l2_host = memory_->TryTranslateWrite(l2_pa);
            if (!l2_host) {
                RaiseAbort(p, ArmFaultStatus::kExternalAbortTranslation2, kIsWrite);
                return nullptr;
            }
            ArmL2Pte l2_pte;
            l2_pte.word = *reinterpret_cast<uint32_t*>(l2_host);

            switch (l2_pte.fault.type) {
            case 0:
                RaiseAbort(p, ArmFaultStatus::kTranslationPage, kIsWrite);
                return nullptr;
            case 3:
                /* WinCE NK ksarm.h:72 — ARMV6_MMU_PTL2_SMALL_XN = 1<<0,
                   so PTL2_SMALL_PAGE|XN = 2|1 = 3. ksarm.h:85 —
                   PREARMV6_MMU_PTL2_SMALL_XN = 0 (no XN, type=3 is fault). */
                if (!modern_v6_fmt) {
                    if (!v6_ext_small) {
                        RaiseAbort(p, ArmFaultStatus::kTranslationPage, kIsWrite);
                        return nullptr;
                    }
                    /* ARM1136 TRM Table 6-16/Fig 6-5: 4 KB extended small
                       page, single AP at bits[5:4], no nG (global). */
                    const uint32_t ap = (l2_pte.word >> 4) & 3u;
                    if (!skip_ap && !ApPermits<kAccess>(ap, is_user_mode)) {
                        RaiseAbort(p, ArmFaultStatus::kPermissionPage, kIsWrite);
                        return nullptr;
                    }
                    new_slot.pte             = l2_pte.word;
                    new_slot.global          = true;
                    effective_address        = ArmExtSmallPagePa(l2_pte.word, p);
                    break;
                }
                if constexpr (kAccess == ArmMmuAccess::kExecute) {
                    RaiseAbort(p, ArmFaultStatus::kPermissionPage, kIsWrite);
                    return nullptr;
                } else {
                    /* Clear XN so TLB-hit fast path decodes as 4 KB small
                       page (type=2), not legacy 1 KB extended small (type=3). */
                    l2_pte.word &= ~1u;
                }
                [[fallthrough]];
            case 2: {
                bool ap_ok;
                if (modern_v6_fmt) {
                    const uint32_t ap = ((l2_pte.word >> 4) & 3u) |
                                        (((l2_pte.word >> 9) & 1u) << 2);
                    ap_ok = ApPermitsV6<kAccess>(ap, is_user_mode);
                } else {
                    const uint32_t ap = (l2_pte.small_page.aps >> ((p >> 9) & 6u)) & 3u;
                    ap_ok = ApPermits<kAccess>(ap, is_user_mode);
                }
                if (!skip_ap && !ap_ok) {
                    RaiseAbort(p, ArmFaultStatus::kPermissionPage, kIsWrite);
                    return nullptr;
                }
                new_slot.pte             = l2_pte.word;
                /* ARM DDI 0406C.c B3.5 Fig B3-5: L2 small page nG at bit[11]. */
                new_slot.global          = !((l2_pte.word >> 11) & 1u);
                effective_address        = (l2_pte.small_page.small_page_base << 12) | (p & 0x0FFFu);
                break;
            }
            case 1: {
                if (modern_v6_fmt) {
                    LOG(Caution, "MMU walk: v6+ L2 large page not implemented "
                            "(va=0x%08X L2_pte=0x%08X) — AP[2] bit position "
                            "unverified in available references.\n",
                        p, l2_pte.word);
                    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
                }
                const uint32_t ap = (l2_pte.large_page.aps >> ((p >> 13) & 6u)) & 3u;
                if (!skip_ap && !ApPermits<kAccess>(ap, is_user_mode)) {
                    RaiseAbort(p, ArmFaultStatus::kPermissionPage, kIsWrite);
                    return nullptr;
                }
                new_slot.pte             = l2_pte.word;
                /* ARM DDI 0406C.c B3.5 Fig B3-5: L2 large page nG at bit[11]. */
                new_slot.global          = !((l2_pte.word >> 11) & 1u);
                effective_address        = (l2_pte.large_page.large_page_base << 16) | (p & 0xFFFFu);
                break;
            }
            }
            break;
        }

        case ArmL1PteType::kSection: {
            if (l1_pte.section.domain != 0u) {
                RaiseAbort(p, ArmFaultStatus::kDomainSection, kIsWrite);
                return nullptr;
            }
            bool ap_ok;
            uint32_t v7_ap = 0;
            if (modern_v6_fmt) {
                /* WinCE NK ksarm.h:76 ARMV6_MMU_PTL1_KR0=0x8400 — bits[11:10]=AP[1:0],
                   bit[15]=APX. Subpage AP layout is v5-only. */
                v7_ap = ((l1_pte.word >> 10) & 3u) |
                        (((l1_pte.word >> 15) & 1u) << 2);
                ap_ok = ApPermitsV6<kAccess>(v7_ap, is_user_mode);
            } else {
                ap_ok = ApPermits<kAccess>(l1_pte.section.ap, is_user_mode);
            }
            if (!skip_ap && !ap_ok) {
                LOG(Caution, "MMU walk: L1 section permission denied "
                        "va=0x%08X L1_pte=0x%08X v7_ap=%u access=%u user=%u\n",
                    p, l1_pte.word, v7_ap,
                    static_cast<unsigned>(kAccess),
                    static_cast<unsigned>(is_user_mode));
                RaiseAbort(p, ArmFaultStatus::kPermissionSection, kIsWrite);
                return nullptr;
            }
            /* PTEType=0 in stored TLB word marks the slot as a cached section. */
            new_slot.pte             = l1_pte.word & ~static_cast<uint32_t>(3);
            /* ARM DDI 0406C.c B3.5 Fig B3-4: L1 Section nG at bit[17]. */
            new_slot.global          = !((l1_pte.word >> 17) & 1u);
            effective_address        = (l1_pte.section.section_base << 20) | (p & 0x000FFFFFu);
            break;
        }

        case ArmL1PteType::kFine: {
            if (modern_v6_fmt) {
                LOG(Caution, "MMU walk: v7 L1 type=3 (reserved) "
                        "(va=0x%08X L1_pa=0x%08X L1_pte=0x%08X).\n",
                    p, l1_pa, l1_pte.word);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            if (l1_pte.fine.domain != 0u) {
                RaiseAbort(p, ArmFaultStatus::kDomainPage, kIsWrite);
                return nullptr;
            }
            /* v4/v5 Fine page-table descriptors carry no nG bit (ARM
               DDI 0406C.c Appendix D15 §D15.6 Table D15-10), so v5
               entries populate global=true. */
            const uint32_t l2_pa = (l1_pte.fine.page_table_base << 14) | (((p >> 10) & 0x3FFu) << 2);
            uint8_t* l2_host = memory_->TryTranslateWrite(l2_pa);
            if (!l2_host) {
                RaiseAbort(p, ArmFaultStatus::kExternalAbortTranslation2, kIsWrite);
                return nullptr;
            }
            ArmL2Pte l2_pte;
            l2_pte.word = *reinterpret_cast<uint32_t*>(l2_host);

            switch (l2_pte.fault.type) {
            case 0:
                RaiseAbort(p, ArmFaultStatus::kTranslationPage, kIsWrite);
                return nullptr;
            case 1: {
                const uint32_t ap = (l2_pte.large_page.aps >> ((p >> 13) & 6u)) & 3u;
                if (!skip_ap && !ApPermits<kAccess>(ap, is_user_mode)) {
                    RaiseAbort(p, ArmFaultStatus::kPermissionPage, kIsWrite);
                    return nullptr;
                }
                new_slot.pte             = l2_pte.word;
                new_slot.global          = true;
                effective_address        = (l2_pte.large_page.large_page_base << 16) | (p & 0xFFFFu);
                break;
            }
            case 2: {
                const uint32_t ap = (l2_pte.small_page.aps >> ((p >> 9) & 6u)) & 3u;
                if (!skip_ap && !ApPermits<kAccess>(ap, is_user_mode)) {
                    RaiseAbort(p, ArmFaultStatus::kPermissionPage, kIsWrite);
                    return nullptr;
                }
                new_slot.pte             = l2_pte.word;
                new_slot.global          = true;
                effective_address        = (l2_pte.small_page.small_page_base << 12) | (p & 0x0FFFu);
                break;
            }
            case 3: {
                if (!skip_ap && !ApPermits<kAccess>(l2_pte.extended_small_page.ap, is_user_mode)) {
                    RaiseAbort(p, ArmFaultStatus::kPermissionPage, kIsWrite);
                    return nullptr;
                }
                new_slot.pte             = l2_pte.word;
                new_slot.global          = true;
                effective_address        = (l2_pte.extended_small_page.extended_small_page_base << 10) | (p & 0x01FFu);
                break;
            }
            }
            break;
        }
        }

        /* A section/large mapping straddling a backing-region boundary or a
           peripheral hole has no single host_adjust; non-uniform pages are
           never cached fast (the inline probe misses → this walk routes each
           access by its own PA). */
        const bool uniform = memory_->IsSlotRangeUniform(new_slot.pte, effective_address);

        if constexpr (kAccess == ArmMmuAccess::kExecute) last_exec_pa_ = effective_address;

        if constexpr (kAccess == ArmMmuAccess::kWrite) {
            uint8_t* host_ptr = memory_->TryTranslateWrite(effective_address);
            if (host_ptr) {
                if (uniform) {
                    FillFastTlb(tlb_unit, p, host_ptr, effective_address,
                                current_asid, new_slot.global, /*writable=*/true);
                }
                NoteCodeTracking<kAccess>(state_, effective_address);
                return host_ptr;
            }
            SetIoPending(effective_address);
            return nullptr;
        } else {
            uint8_t* ram_host = memory_->TryTranslateWrite(effective_address);
            if (ram_host) {
                if (uniform) {
                    /* kReadWrite (SWP) checked write permission in the walk so it
                       caches writable; kRead/kExecute cache read-only — a later
                       store re-walks once to verify write perm and set writable. */
                    const bool writable = (kAccess == ArmMmuAccess::kReadWrite);
                    FillFastTlb(tlb_unit, p, ram_host, effective_address,
                                current_asid, new_slot.global, writable);
                }
                NoteCodeTracking<kAccess>(state_, effective_address);
                return ram_host;
            }
            uint8_t* flash_host = memory_->TryTranslate(effective_address);
            if (flash_host) {
                /* Cache XIP flash/ROM pages read-only too. A guest paging from
                   flash (iPaq) keeps one HW L2 entry per 1 MB region and relies
                   on the TLB retaining the rest; not caching here re-walks every
                   access and faults whenever that entry was oscillated away. */
                if (uniform) {
                    FillFastTlb(tlb_unit, p, flash_host, effective_address,
                                current_asid, new_slot.global, /*writable=*/false);
                }
                NoteCodeTracking<kAccess>(state_, effective_address);
                return flash_host;
            }
            SetIoPending(effective_address);
            return nullptr;
        }
    }
}

uint8_t* ArmMmu::TranslateRead(ArmCpuState* cpu_state, uint32_t va) {
    return MapGuestVirtualToHost<ArmMmuAccess::kRead>(cpu_state, va);
}

uint8_t* ArmMmu::TranslateWrite(ArmCpuState* cpu_state, uint32_t va) {
    return MapGuestVirtualToHost<ArmMmuAccess::kWrite>(cpu_state, va);
}

uint8_t* ArmMmu::TranslateReadWrite(ArmCpuState* cpu_state, uint32_t va) {
    return MapGuestVirtualToHost<ArmMmuAccess::kReadWrite>(cpu_state, va);
}

uint8_t* ArmMmu::TranslateExecute(ArmCpuState* cpu_state, uint32_t va) {
    return MapGuestVirtualToHost<ArmMmuAccess::kExecute>(cpu_state, va);
}
