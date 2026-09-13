#include "arm_page_walker.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/arm_processor_config.h"
#include "../../cpu/emulated_memory.h"
#include "arm_mmu.h"
#include "arm_mmu_ap_permits.h"
#include "arm_pte.h"
#include "arm_tlb_ops.h"

REGISTER_SERVICE(ArmPageWalker);

bool ArmPageWalker::ShouldRegister() {
    return emu_.Get<BoardContext>().GetCpuArch() == CpuArch::Arm;
}

void ArmPageWalker::OnReady() {
    mmu_              = &emu_.Get<ArmMmu>();
    state_p_          = mmu_->State();
    memory_           = &emu_.Get<EmulatedMemory>();
    processor_config_ = &emu_.Get<ArmProcessorConfig>();
    mmu_->BindWalker(this);
}

void ArmPageWalker::SetInjectionBand(uint32_t va_base, uint32_t pa_base, uint32_t size) {
    injection_band_va_   = va_base;
    injection_band_pa_   = pa_base;
    injection_band_size_ = size;
}

uint8_t* ArmPageWalker::ServeInjectionBand(uint32_t va, ArmMmuAccess access) {
    if (injection_band_size_ == 0u) return nullptr;
    const uint32_t off = va - injection_band_va_;
    if (off >= injection_band_size_) return nullptr;
    const uint32_t pa = injection_band_pa_ + off;
    const bool is_write = (access == ArmMmuAccess::kWrite || access == ArmMmuAccess::kReadWrite);
    uint8_t* host = is_write ? memory_->TryTranslateWrite(pa) : memory_->TryTranslate(pa);
    if (!host) return nullptr;
    if (access == ArmMmuAccess::kExecute) last_exec_pa_ = pa;
    return host;
}

template <ArmMmuAccess kAccess, bool kForceUser>
uint8_t* ArmPageWalker::MapGuestVirtualToHost(ArmCpuState* cpu_state, uint32_t p) {
    ArmMmuState& state_ = *state_p_;
    constexpr bool kIsWrite = (kAccess == ArmMmuAccess::kWrite ||
                               kAccess == ArmMmuAccess::kReadWrite);
    mmu_->ClearIoPending();

    /* ARM1136 TRM Table 3-44, c1 bit[23] XP (p. 3-64): "0 = Subpage AP bits
       enabled", "1 = Subpage AP bits disabled (ARMv6 mode)". */
    const bool modern_v6_fmt = processor_config_->HasCp15V6() &&
                               state_.effective_control_register.bits.xp;

    /* ARM1136 TRM Table 6-16: with XP=0 a coarse L2 type=3 is a 4 KB
       extended small page (base[31:12], single AP[5:4]); decoding it via
       the tiny_page union (1 KB, base[31:10]) maps the wrong PA
       and the access re-faults forever. v5 cores keep the 1 KB decode. */
    const bool v6_ext_small = processor_config_->HasCp15V6() &&
                              !state_.effective_control_register.bits.xp;

    /* ARM DDI 0406C.c B3.19.3 TranslateAddressV (p. B3-1504): "mva =
       FCSETranslate(va)" precedes the SCTLR.M test, and the stage-1-disabled
       branch takes "TranslateAddressVS1Off(mva)", whose result is
       "physicaladdress = '00000000':va" over that mva (p. B3-1505). */
    p = ArmFcseFold(p, state_.process_id);

    if (!state_.effective_control_register.bits.m) {
        uint8_t* host = memory_->TryTranslate(p);
        if (host) {
            if constexpr (kAccess == ArmMmuAccess::kExecute) last_exec_pa_ = p;
            return host;
        }
        mmu_->SetIoPending(p);
        return nullptr;
    }

    ArmTlbUnit* tlb_unit = (kAccess == ArmMmuAccess::kExecute)
        ? &state_.instruction_tlb : &state_.data_tlb;

    const bool is_user_mode =
        kForceUser || (cpu_state->cpsr.bits.mode == ArmMode::kUser);
    /* ARM DDI 0406C.c B3.9.1: ASID is CONTEXTIDR[7:0]. */
    const uint8_t current_asid = static_cast<uint8_t>(state_.contextidr & 0xFFu);
    /* ARM DDI 0406C.c Table D15-7: AP=00 access depends on SCTLR.{S,R}. */
    const bool sctlr_s = state_.effective_control_register.bits.s != 0u;
    const bool sctlr_r = state_.effective_control_register.bits.r != 0u;

    /* Domain check happens on the VALID final-level descriptor, AP only for
       Client domains (ARM DDI 0406C B3.12.3 p.B3-1398; B4.1.43 DACR fields:
       00 fault, 01 Client, 10 reserved/UNPREDICTABLE = fault fail-closed,
       11 Manager skips AP). Linux maps vectors/IO in domains 1/2. */
    const uint32_t dacr = state_.domain_access_control;
    uint32_t effective_address = 0;

    /* Set-associative fast path: scan the set's ways for a live match (the
       inline JIT probe only checked way 0), promote a hit to way 0 (MRU) so the
       inline probe finds it next time, then resolve the host without a walk. A
       write to a page cached read-only falls through to the walk to re-check. */
    const uint32_t va_page  = p & 0xFFFFF000u;
    const uint32_t set_base = ArmTlbSetBase(p);
    if constexpr (!kForceUser) {
        const int hit_way =
            ArmTlbMatchWay(tlb_unit, set_base, va_page, current_asid, kIsWrite);
        if (hit_way >= 0) {
            ArmTlbPromote(tlb_unit, set_base, hit_way);
            const ArmTlbEntry& fast = tlb_unit->entries[set_base];
            const uint32_t pa = fast.pa_page | (p & 0x0FFFu);
            if constexpr (kAccess == ArmMmuAccess::kExecute) last_exec_pa_ = pa;
            ArmNoteCodeTracking<kAccess>(state_, pa);
            return reinterpret_cast<uint8_t*>(
                static_cast<uintptr_t>(p) + fast.va_addend);
        }

        /* I/O fast path: a cached device page routes straight to the
           PeripheralDispatcher (SetIoPending) without a walk. Execute never
           caches I/O - code fetched from MMIO is not a real path. */
        if constexpr (kAccess != ArmMmuAccess::kExecute) {
            const int io_way = ArmTlbMatchIoWay(tlb_unit, set_base, va_page,
                                                current_asid, kIsWrite);
            if (io_way >= 0) {
                const ArmTlbEntry& io =
                    tlb_unit->entries[set_base + static_cast<uint32_t>(io_way)];
                mmu_->SetIoPending(io.pa_page | (p & 0x0FFFu));
                return nullptr;
            }
        }
    }

    /* Fast-path miss - walk the in-RAM page table. */
    {
        const uint32_t l1_pa = ArmL1DescriptorAddress(p, state_.ttbcr,
                                                      state_.translation_table_base.word, state_.ttbr1);
        uint8_t* l1_host = memory_->TryTranslateWrite(l1_pa);
        if (!l1_host) {
            mmu_->RaiseAbort(p, ArmFaultStatus::kExternalAbortTranslation1, 0u, kAccess);
            return nullptr;
        }
        ArmL1Pte l1_pte;
        l1_pte.word = *reinterpret_cast<uint32_t*>(l1_host);

        struct {
            uint32_t span_bytes    = 0x1000u;
            bool     global        = false;
            bool     fast_fillable = true;
        } new_slot{};

        switch (l1_pte.fault.type) {
        case ArmL1PteType::kFault:
            if (uint8_t* band = ServeInjectionBand(p, kAccess)) return band;
            mmu_->RaiseAbort(p, ArmFaultStatus::kTranslationSection, 0u, kAccess);
            return nullptr;

        case ArmL1PteType::kCoarse: {
            const uint32_t domain    = l1_pte.coarse.domain;
            const uint32_t dom_field = (dacr >> (domain << 1)) & 3u;
            const uint32_t l2_pa = (l1_pte.coarse.page_table_base << 10) | (((p >> 12) & 0xFFu) << 2);
            uint8_t* l2_host = memory_->TryTranslateWrite(l2_pa);
            if (!l2_host) {
                mmu_->RaiseAbort(p, ArmFaultStatus::kExternalAbortTranslation2, domain, kAccess);
                return nullptr;
            }
            ArmL2Pte l2_pte;
            l2_pte.word = *reinterpret_cast<uint32_t*>(l2_host);

            switch (l2_pte.fault.type) {
            case 0:
                mmu_->RaiseAbort(p, ArmFaultStatus::kTranslationPage, domain, kAccess);
                return nullptr;
            case 3:
                if (!modern_v6_fmt) {
                    if (!v6_ext_small) {
                        mmu_->RaiseAbort(p, ArmFaultStatus::kTranslationPage, domain, kAccess);
                        return nullptr;
                    }
                    /* ARM1136 TRM Table 6-16/Fig 6-5: 4 KB extended small
                       page, single AP at bits[5:4], no nG (global). */
                    if (!(dom_field & 1u)) {
                        mmu_->RaiseAbort(p, ArmFaultStatus::kDomainPage, domain, kAccess);
                        return nullptr;
                    }
                    const uint32_t ap = (l2_pte.word >> 4) & 3u;
                    if (dom_field == 1u && !ApPermits<kAccess>(ap, is_user_mode, sctlr_s, sctlr_r)) {
                        mmu_->RaiseAbort(p, ArmFaultStatus::kPermissionPage, domain, kAccess);
                        return nullptr;
                    }
                    new_slot.global     = true;
                    effective_address   = ArmExtSmallPagePa(l2_pte.word, p);
                    break;
                }
                if (!(dom_field & 1u)) {
                    mmu_->RaiseAbort(p, ArmFaultStatus::kDomainPage, domain, kAccess);
                    return nullptr;
                }
                if constexpr (kAccess == ArmMmuAccess::kExecute) {
                    mmu_->RaiseAbort(p, ArmFaultStatus::kPermissionPage, domain, kAccess);
                    return nullptr;
                }
                [[fallthrough]];
            case 2: {
                if (!(dom_field & 1u)) {
                    mmu_->RaiseAbort(p, ArmFaultStatus::kDomainPage, domain, kAccess);
                    return nullptr;
                }
                bool ap_ok;
                if (modern_v6_fmt) {
                    const uint32_t ap = ((l2_pte.word >> 4) & 3u) |
                                        (((l2_pte.word >> 9) & 1u) << 2);
                    ap_ok = ApPermitsV6<kAccess>(ap, is_user_mode);
                } else {
                    /* ARM DDI 0406C.c p. D15-2609 Subpage support: four
                       equal subpages, subpage 0 lowest - a 4 KB Small
                       page's subpage index is VA[11:10]. */
                    const uint32_t ap = ArmL2SubpageAp(l2_pte, (p >> 10) & 3u);
                    ap_ok = ApPermits<kAccess>(ap, is_user_mode, sctlr_s, sctlr_r);
                }
                if (dom_field == 1u && !ap_ok) {
                    mmu_->RaiseAbort(p, ArmFaultStatus::kPermissionPage, domain, kAccess);
                    return nullptr;
                }
                /* ARM DDI 0406C.c B3.5 Fig B3-5: L2 small page nG at bit[11]. */
                new_slot.global         = !((l2_pte.word >> 11) & 1u);
                effective_address       = (l2_pte.small_page.small_page_base << 12) | (p & 0x0FFFu);
                break;
            }
            case 1: {
                if (modern_v6_fmt) {
                    if (!(dom_field & 1u)) {
                        mmu_->RaiseAbort(p, ArmFaultStatus::kDomainPage, domain, kAccess);
                        return nullptr;
                    }
                    /* ARM DDI 0406C.c Figure B3-5 Large page: XN [15],
                       AP[2] [9], AP[1:0] [5:4], nG [11]. */
                    if constexpr (kAccess == ArmMmuAccess::kExecute) {
                        if (l2_pte.large_page.xn) {
                            mmu_->RaiseAbort(p, ArmFaultStatus::kPermissionPage,
                                       domain, kAccess);
                            return nullptr;
                        }
                    }
                    const uint32_t ap = ((l2_pte.word >> 4) & 3u) | (((l2_pte.word >> 9) & 1u) << 2);
                    if (dom_field == 1u && !ApPermitsV6<kAccess>(ap, is_user_mode)) {
                        mmu_->RaiseAbort(p, ArmFaultStatus::kPermissionPage, domain,
                                   kAccess);
                        return nullptr;
                    }
                    new_slot.span_bytes = 0x10000u;
                    new_slot.global     = !((l2_pte.word >> 11) & 1u);
                    effective_address   =
                        (l2_pte.large_page.large_page_base << 16) | (p & 0xFFFFu);
                    break;
                }
                if (!(dom_field & 1u)) {
                    mmu_->RaiseAbort(p, ArmFaultStatus::kDomainPage, domain, kAccess);
                    return nullptr;
                }
                /* ARM DDI 0406C.c p. D15-2609 Subpage support: four equal
                   subpages, subpage 0 lowest - a 64 KB Large page's subpage
                   index is VA[15:14]. */
                const uint32_t ap = ArmL2SubpageAp(l2_pte, (p >> 14) & 3u);
                if (dom_field == 1u && !ApPermits<kAccess>(ap, is_user_mode, sctlr_s, sctlr_r)) {
                    mmu_->RaiseAbort(p, ArmFaultStatus::kPermissionPage, domain, kAccess);
                    return nullptr;
                }
                new_slot.span_bytes     = 0x10000u;
                /* ARM DDI 0406C.c B3.5 Fig B3-5: L2 large page nG at bit[11]. */
                new_slot.global         = !((l2_pte.word >> 11) & 1u);
                effective_address       = (l2_pte.large_page.large_page_base << 16) | (p & 0xFFFFu);
                break;
            }
            }
            if (!mmu_->MapPhysicalAddress(effective_address, p, domain, kAccess, effective_address))
                return nullptr;
            break;
        }

        case ArmL1PteType::kSection: {
            const ArmSupersectionFormat format = ArmEffectiveSupersectionFormat(
                processor_config_->SupersectionFormat(), state_.effective_control_register.bits.xp);
            const auto translation =
                ArmTranslateSection(l1_pte.word, p, format);
            const uint32_t domain    = translation.domain;
            const uint32_t dom_field = (dacr >> (domain << 1)) & 3u;
            if (!(dom_field & 1u)) {
                mmu_->RaiseAbort(p, ArmFaultStatus::kDomainSection, domain, kAccess);
                return nullptr;
            }
            bool ap_ok;
            uint32_t v7_ap = 0;
            if (modern_v6_fmt) {
                v7_ap = ((l1_pte.word >> 10) & 3u) | (((l1_pte.word >> 15) & 1u) << 2);
                ap_ok = ApPermitsV6<kAccess>(v7_ap, is_user_mode);
            } else {
                ap_ok = ApPermits<kAccess>(l1_pte.section.ap, is_user_mode, sctlr_s, sctlr_r);
            }
            if (dom_field == 1u && !ap_ok) {
                LOG(Caution, "MMU walk: L1 section permission denied "
                        "va=0x%08X L1_pte=0x%08X v7_ap=%u access=%u user=%u\n",
                    p, l1_pte.word, v7_ap,
                    static_cast<unsigned>(kAccess),
                    static_cast<unsigned>(is_user_mode));
                mmu_->RaiseAbort(p, ArmFaultStatus::kPermissionSection, domain, kAccess);
                return nullptr;
            }
            if (!mmu_->MapPhysicalAddress(translation.physical_address, p, domain, kAccess,
                                          effective_address)) return nullptr;
            new_slot.span_bytes = translation.span_bytes;
            /* ARM DDI 0406C.c B3.5 Fig B3-4: L1 Section nG at bit[17]. */
            new_slot.global          = !((l1_pte.word >> 17) & 1u);
            break;
        }
        case ArmL1PteType::kFine: {
            /* ARM DDI 0406C.c D12.6 / D15.6.3: the fine second-level page
               table format is not supported from ARMv6, at any SCTLR.XP. */
            if (processor_config_->HasCp15V6()) {
                LOG(Caution, "MMU walk: L1 type=3 (Fine) on ARMv6+ "
                        "(va=0x%08X L1_pa=0x%08X L1_pte=0x%08X).\n",
                    p, l1_pa, l1_pte.word);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            const uint32_t domain    = l1_pte.fine.domain;
            const uint32_t dom_field = (dacr >> (domain << 1)) & 3u;
            /* v4/v5 Fine page-table descriptors carry no nG bit (ARM
               DDI 0406C.c Appendix D15 §D15.6 Table D15-10), so v5
               entries populate global=true. */
            /* ARM DDI 0406C.c Figure D15-1: second-level descriptor PA =
               table base[31:12] | (VA[19:10] << 2). */
            const uint32_t l2_pa = (l1_pte.fine.page_table_base << 12) |
                                   (((p >> 10) & 0x3FFu) << 2);
            uint8_t* l2_host = memory_->TryTranslateWrite(l2_pa);
            if (!l2_host) {
                mmu_->RaiseAbort(p, ArmFaultStatus::kExternalAbortTranslation2, domain, kAccess);
                return nullptr;
            }
            ArmL2Pte l2_pte;
            l2_pte.word = *reinterpret_cast<uint32_t*>(l2_host);

            switch (l2_pte.fault.type) {
            case ArmL2PteType::kFault:
                mmu_->RaiseAbort(p, ArmFaultStatus::kTranslationPage, domain, kAccess);
                return nullptr;
            case ArmL2PteType::kLargePage: {
                if (!(dom_field & 1u)) {
                    mmu_->RaiseAbort(p, ArmFaultStatus::kDomainPage, domain, kAccess);
                    return nullptr;
                }
                /* ARM DDI 0406C.c p. D15-2609 Subpage support: four equal
                   subpages, subpage 0 lowest - a 64 KB Large page's subpage
                   index is VA[15:14]. */
                const uint32_t ap = ArmL2SubpageAp(l2_pte, (p >> 14) & 3u);
                if (dom_field == 1u && !ApPermits<kAccess>(ap, is_user_mode, sctlr_s, sctlr_r)) {
                    mmu_->RaiseAbort(p, ArmFaultStatus::kPermissionPage, domain, kAccess);
                    return nullptr;
                }
                new_slot.span_bytes      = 0x10000u;
                new_slot.global          = true;
                effective_address        = (l2_pte.large_page.large_page_base << 16) | (p & 0xFFFFu);
                break;
            }
            case ArmL2PteType::kSmallPage: {
                if (!(dom_field & 1u)) {
                    mmu_->RaiseAbort(p, ArmFaultStatus::kDomainPage, domain, kAccess);
                    return nullptr;
                }
                /* ARM DDI 0406C.c p. D15-2609 Subpage support: four equal
                   subpages, subpage 0 lowest - a 4 KB Small page's subpage
                   index is VA[11:10]. */
                const uint32_t ap = ArmL2SubpageAp(l2_pte, (p >> 10) & 3u);
                if (dom_field == 1u && !ApPermits<kAccess>(ap, is_user_mode, sctlr_s, sctlr_r)) {
                    mmu_->RaiseAbort(p, ArmFaultStatus::kPermissionPage, domain, kAccess);
                    return nullptr;
                }
                new_slot.global          = true;
                effective_address        = (l2_pte.small_page.small_page_base << 12) | (p & 0x0FFFu);
                break;
            }
            case ArmL2PteType::kTinyPage: {
                if (!(dom_field & 1u)) {
                    mmu_->RaiseAbort(p, ArmFaultStatus::kDomainPage, domain, kAccess);
                    return nullptr;
                }
                if (dom_field == 1u &&
                    !ApPermits<kAccess>(l2_pte.tiny_page.ap, is_user_mode,
                                    sctlr_s, sctlr_r)) {
                    mmu_->RaiseAbort(p, ArmFaultStatus::kPermissionPage, domain, kAccess);
                    return nullptr;
                }
                new_slot.global          = true;
                /* ARM DDI 0406C.c Table D15-10 / Figure D15-1: 1 KB Tiny
                   page - PA = descriptor bits[31:10] | VA[9:0]. */
                effective_address        =
                    (l2_pte.tiny_page.tiny_page_base << 10) | (p & 0x03FFu);
                /* ARM DDI 0406C.c Table D15-10: a Tiny page maps 1 KB. */
                new_slot.span_bytes      = 0x400u;
                new_slot.fast_fillable   = false;
                break;
            }
            }
            if (!mmu_->MapPhysicalAddress(effective_address, p, domain, kAccess, effective_address))
                return nullptr;
            break;
        }
        }

        const bool uniform = new_slot.fast_fillable && memory_->IsSlotRangeUniform(new_slot.span_bytes,
                                                         effective_address);

        if constexpr (kAccess == ArmMmuAccess::kExecute) last_exec_pa_ = effective_address;

        if constexpr (kAccess == ArmMmuAccess::kWrite) {
            uint8_t* host_ptr = memory_->TryTranslateWrite(effective_address);
            if (host_ptr) {
                if (uniform) {
                    FillFastTlb(tlb_unit, p, host_ptr, effective_address, current_asid, 
					            new_slot.global, /*writable=*/true, new_slot.span_bytes);
                }
                ArmNoteCodeTracking<kAccess>(state_, effective_address);
                return host_ptr;
            }
            /* Cache io only for a PA with no read backing. A read-backed flash/ROM
               PA already holds a RAM read entry; adding an io entry gives the page
               two TLB entry-types, and the way-0 inline io probe (one type per page)
               then resolves the page's reads to MMIO. */
            if (new_slot.fast_fillable && !memory_->TryTranslate(effective_address)) {
                FillFastTlbIo(tlb_unit, p, effective_address, current_asid,
                              new_slot.global, /*writable=*/true, new_slot.span_bytes);
            }
            mmu_->SetIoPending(effective_address);
            return nullptr;
        } else {
            uint8_t* ram_host = memory_->TryTranslateWrite(effective_address);
            if (ram_host) {
                if (uniform) {
                    /* kReadWrite (SWP) checked write permission in the walk so it
                       caches writable; kRead/kExecute cache read-only - a later
                       store re-walks once to verify write perm and set writable. */
                    const bool writable = (kAccess == ArmMmuAccess::kReadWrite);
                    FillFastTlb(tlb_unit, p, ram_host, effective_address,
                                current_asid, new_slot.global, writable, new_slot.span_bytes);
                }
                ArmNoteCodeTracking<kAccess>(state_, effective_address);
                return ram_host;
            }
            uint8_t* flash_host = memory_->TryTranslate(effective_address);
            if (flash_host) {
                /* Cache XIP flash/ROM pages read-only too. A guest paging from
                   flash (iPaq) keeps one HW L2 entry per 1 MB region and relies
                   on the TLB retaining the rest; not caching here re-walks every
                   access and faults whenever that entry was oscillated away. */
                if (uniform) {
                    FillFastTlb(tlb_unit, p, flash_host, effective_address, current_asid,
					            new_slot.global, /*writable=*/false, new_slot.span_bytes);
                }
                ArmNoteCodeTracking<kAccess>(state_, effective_address);
                return flash_host;
            }
            if constexpr (kAccess != ArmMmuAccess::kExecute) {
                if (new_slot.fast_fillable) {
                    FillFastTlbIo(tlb_unit, p, effective_address, current_asid, new_slot.global, 
					              /*writable=*/kAccess == ArmMmuAccess::kReadWrite,
                                  new_slot.span_bytes);
                }
            }
            mmu_->SetIoPending(effective_address);
            return nullptr;
        }
    }
}

uint8_t* ArmPageWalker::TranslateRead(ArmCpuState* cpu_state, uint32_t va) {
    return MapGuestVirtualToHost<ArmMmuAccess::kRead>(cpu_state, va);
}

uint8_t* ArmPageWalker::TranslateWrite(ArmCpuState* cpu_state, uint32_t va) {
    return MapGuestVirtualToHost<ArmMmuAccess::kWrite>(cpu_state, va);
}

uint8_t* ArmPageWalker::TranslateReadWrite(ArmCpuState* cpu_state, uint32_t va) {
    return MapGuestVirtualToHost<ArmMmuAccess::kReadWrite>(cpu_state, va);
}

uint8_t* ArmPageWalker::TranslateExecute(ArmCpuState* cpu_state, uint32_t va) {
    return MapGuestVirtualToHost<ArmMmuAccess::kExecute>(cpu_state, va);
}

uint8_t* ArmPageWalker::TranslateUserRead(ArmCpuState* cpu_state, uint32_t va) {
    return MapGuestVirtualToHost<ArmMmuAccess::kRead, true>(cpu_state, va);
}

uint8_t* ArmPageWalker::TranslateUserWrite(ArmCpuState* cpu_state, uint32_t va) {
    return MapGuestVirtualToHost<ArmMmuAccess::kWrite, true>(cpu_state, va);
}
