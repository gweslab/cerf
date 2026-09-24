#include "mips_cpu.h"

#include "../../boot/rom_parser_service.h"
#include "../../core/cerf_emulator.h"
#include "../../cpu/mips_processor_config.h"
#include "../../host/guest_deep_sleep.h"
#include "../../state/state_stream.h"

REGISTER_SERVICE(MipsCpu);

void MipsCpu::OnReady() { ResetState(); }

void MipsCpu::ResetState() {
    auto& cfg = emu_.Get<MipsProcessorConfig>();

    state_ = MipsCpuState{};
    state_.cp0_prid       = cfg.Prid();
    state_.nb_tlb         = cfg.TlbSize();
    state_.tlb_in_use     = state_.nb_tlb;
    state_.min_page_shift = cfg.MinPageShift();
    state_.phys_addr_mask = cfg.PhysAddrMask();

    state_.pc = emu_.Get<RomParserService>().EntryVa();
}

void __fastcall MipsCpu::HibernateHelper(uint32_t next_pc, MipsCpu* cpu) {
    cpu->state_.pc = next_pc;
    cpu->emu_.Get<GuestDeepSleep>().Enter();
}

template <typename F>
constexpr void MipsCpu::VisitState(MipsCpuState& s, F& field) {
    field("gpr", s.gpr);
    field("hi", s.hi);
    field("lo", s.lo);
    field("pc", s.pc);
    field("branch_state", s.branch_state);
    field("btarget", s.btarget);
    field("bcond", s.bcond);
    field("cp0_index", s.cp0_index);
    field("cp0_random", s.cp0_random);
    field("cp0_entrylo0", s.cp0_entrylo0);
    field("cp0_entrylo1", s.cp0_entrylo1);
    field("cp0_context", s.cp0_context);
    field("cp0_pagemask", s.cp0_pagemask);
    field("cp0_wired", s.cp0_wired);
    field("cp0_badvaddr", s.cp0_badvaddr);
    field("cp0_count", s.cp0_count);
    field("cp0_entryhi", s.cp0_entryhi);
    field("cp0_compare", s.cp0_compare);
    field("cp0_status", s.cp0_status);
    field("cp0_cause", s.cp0_cause);
    field("cp0_epc", s.cp0_epc);
    field("cp0_prid", s.cp0_prid);
    field("cp0_config", s.cp0_config);
    field("cp0_watchlo", s.cp0_watchlo);
    field("cp0_watchhi", s.cp0_watchhi);
    field("cp0_taglo", s.cp0_taglo);
    field("cp0_taghi", s.cp0_taghi);
    field("cp0_errorepc", s.cp0_errorepc);
    field("cp0_lladdr", s.cp0_lladdr);
    field("cp0_xcontext", s.cp0_xcontext);
    field("cp0_ecc", s.cp0_ecc);
    for (MipsTlbEntry& e : s.tlb) {
        field("tlb_vpn", e.vpn);
        field("tlb_page_mask", e.page_mask);
        field("tlb_asid", e.asid);
        field("tlb_g", e.g);
        field("tlb_v0", e.v0);
        field("tlb_d0", e.d0);
        field("tlb_c0", e.c0);
        field("tlb_v1", e.v1);
        field("tlb_d1", e.d1);
        field("tlb_c1", e.c1);
        field.Skip(e.pad);
        field("tlb_pfn", e.pfn);
    }
    field("nb_tlb", s.nb_tlb);
    field("tlb_in_use", s.tlb_in_use);
    field("llbit", s.llbit);
    field("ll_addr", s.ll_addr);
    field("reset_pending", s.reset_pending);
    field("deep_sleep", s.deep_sleep);
    field("guest_cycle_counter", s.guest_cycle_counter);
    field("count_anchor", s.count_anchor);
    field("timer_armed", s.timer_armed);
    field("min_page_shift", s.min_page_shift);
    field("phys_addr_mask", s.phys_addr_mask);
    field("isa_mode", s.isa_mode);
    field("btarget_isa", s.btarget_isa);
    field("branch_len", s.branch_len);
}

void MipsCpu::SaveState(StateWriter& w) {
    static_assert(StateVisitCoversAllBytes<MipsCpuState>(
                      [](MipsCpuState& s, StateFieldBytes& f) { VisitState(s, f); }),
                  "MipsCpu::VisitState must name or skip every field of MipsCpuState");
    StateWriteField field(w);
    VisitState(state_, field);
}

void MipsCpu::RestoreState(StateReader& r) {
    StateReadField field(r);
    VisitState(state_, field);
}
