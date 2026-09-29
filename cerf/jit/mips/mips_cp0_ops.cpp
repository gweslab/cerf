#include "mips_cp0_ops.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../cpu/mips_processor_config.h"
#include "mips_core_clock.h"
#include "mips_cpu.h"
#include "mips_cpu_state.h"
#include "mips_mmu.h"
#include "mips_translation_cache.h"

REGISTER_SERVICE(MipsCp0Ops);

void MipsCp0Ops::OnReady() {
    cpu_state_ = emu_.Get<MipsCpu>().State();
    mmu_       = &emu_.Get<MipsMmu>();
    cache_     = &emu_.Get<MipsTranslationCache>();
    config_    = &emu_.Get<MipsProcessorConfig>();
    if (!config_->HasCounter()) return;
    clock_         = &emu_.Get<GuestCycleClock>();
    core_clock_    = &emu_.Get<MipsCoreClock>();
    compare_event_ = clock_->Add([this] { OnCompareMatch(); });
    core_clock_->RegisterCountRateListener([this] { AnchorSavedCount(); });
    OnCpuReset();
}

void MipsCp0Ops::SetCountRatio() {
    const uint64_t cycles = core_clock_->CyclesPerCountTick();
    if (!count_.SetRatio(cycles, 1u)) {
        emu_.Get<Fatal>().Die("MipsCp0Ops: %llu cycles per Count tick overflows the counter",
                              static_cast<unsigned long long>(cycles));
    }
}

void MipsCp0Ops::ArmCompare(uint64_t now) {
    clock_->Arm(compare_event_, count_.NextMatchCycle(cpu_state_->cp0_compare, now));
}

/* IP7 "is set automatically whenever the value of the Count register equals the value of the
   Compare register" (VR4121 UM §10.4); QEMU cp0_timer cpu_mips_timer_expire. */
void MipsCp0Ops::OnCompareMatch() {
    cpu_state_->cp0_cause |= kMipsCauseTimerIp;
    ArmCompare(clock_->Cycles());
}

void MipsCp0Ops::OnCpuReset() {
    if (!config_->HasCounter()) return;
    const uint64_t now = clock_->Cycles();
    SetCountRatio();
    count_.Anchor(now, 0u);
    ArmCompare(now);
}

void MipsCp0Ops::SaveCount() {
    MipsCpuState& s = *cpu_state_;
    if (!config_->HasCounter()) {
        s.count_save           = 0u;
        s.count_save_phase     = 0u;
        s.count_save_phase_den = 0u;
        return;
    }
    const uint64_t now = clock_->Cycles();
    const uint64_t den = count_.PhaseDenominator();
    if (den > UINT32_MAX) {
        emu_.Get<Fatal>().Die("MipsCp0Ops: Count phase denominator %llu does not fit the save",
                              static_cast<unsigned long long>(den));
    }
    s.count_save           = count_.CountAt(now);
    s.count_save_phase     = count_.PhaseAt(now);
    s.count_save_phase_den = static_cast<uint32_t>(den);
}

void MipsCp0Ops::OnCpuStateRestored() {
    if (!config_->HasCounter()) return;
    AnchorSavedCount();
}

void MipsCp0Ops::AnchorSavedCount() {
    const MipsCpuState& s = *cpu_state_;
    const uint64_t now = clock_->Cycles();
    SetCountRatio();
    count_.AnchorAtPhase(now, s.count_save, s.count_save_phase, s.count_save_phase_den);
    ArmCompare(now);
}

uint32_t __fastcall MipsCp0Ops::Mfc0CountHelper(MipsCp0Ops* ops) {
    return ops->count_.CountAt(ops->clock_->Cycles());
}

void __fastcall MipsCp0Ops::TlbwiHelper(MipsCp0Ops* ops) {
    ops->mmu_->WriteIndexed(ops->cpu_state_);
}

void __fastcall MipsCp0Ops::TlbwrHelper(MipsCp0Ops* ops) {
    ops->mmu_->WriteRandom(ops->cpu_state_);
}

void __fastcall MipsCp0Ops::TlbpHelper(MipsCp0Ops* ops) {
    ops->mmu_->Probe(ops->cpu_state_);
}

void __fastcall MipsCp0Ops::TlbrHelper(MipsCp0Ops* ops) {
    ops->mmu_->Read(ops->cpu_state_);
}

uint32_t __fastcall MipsCp0Ops::Mfc0RandomHelper(MipsCp0Ops* ops) {
    return ops->mmu_->RandomIndex(ops->cpu_state_);
}

void __fastcall MipsCp0Ops::Mtc0CountHelper(uint32_t value, MipsCp0Ops* ops) {
    const uint64_t now = ops->clock_->Cycles();
    ops->count_.SetCountAt(now, value);
    ops->ArmCompare(now);
}

void __fastcall MipsCp0Ops::Mtc0CompareHelper(uint32_t value, MipsCp0Ops* ops) {
    MipsCpuState& s = *ops->cpu_state_;
    s.cp0_compare = value;
    s.cp0_cause  &= ~kMipsCauseTimerIp;
    ops->ArmCompare(ops->clock_->Cycles());
}

void __fastcall MipsCp0Ops::Mtc0EntryHiHelper(uint32_t value, MipsCp0Ops* ops) {
    /* helper_mtc0_entryhi (cp0_helper.c:1142): write VPN2+ASID, preserve the
       reserved field, flush on an ASID change. mask = VPN2(VA[31:S+1]) | ASID. */
    MipsCpuState& s = *ops->cpu_state_;
    const uint32_t kMask = MipsVpn2Mask(s.min_page_shift) | 0xFFu;
    const uint32_t old = s.cp0_entryhi;
    const uint32_t val = (value & kMask) | (old & ~kMask);
    s.cp0_entryhi = val;
    if ((old & 0xFFu) != (val & 0xFFu)) {
        ops->cache_->ContextSwitchFlush();
    }
}

void __fastcall MipsCp0Ops::EretHelper(MipsCp0Ops* ops) {
    MipsCpuState& s = *ops->cpu_state_;
    /* MIPS64 Vol2 ERET: ERL takes precedence over EXL. */
    if ((s.cp0_status >> MipsStatusBit::kERL) & 1u) {
        s.pc = s.cp0_errorepc;
        s.cp0_status &= ~(1u << MipsStatusBit::kERL);
    } else {
        s.pc = s.cp0_epc;
        s.cp0_status &= ~(1u << MipsStatusBit::kEXL);
    }
    /* "The ERET instruction loads the ISA mode from bit 0 of the EPC or
       ErrorEPC register" when MIPS16 is enabled (U15509EJ2V0UM 3.4.3). */
    if (ops->config_->HasMips16()) {
        s.isa_mode = s.pc & 1u;
        s.pc &= ~1u;
    }
    s.llbit = 0;
}

void __fastcall MipsCp0Ops::RfeHelper(MipsCp0Ops* ops) {
    MipsCpuState& s = *ops->cpu_state_;
    /* IEc<-IEp, KUc<-KUp, IEp<-IEo, KUp<-KUo; IEo and KUo retain their values
       (TMPR39xx-um Fig 6-7). Status bits: IEc<0> KUc<1> IEp<2> KUp<3> IEo<4>
       KUo<5> (TMPR39xx-um §6.2.3). The Cache register's auto-lock half of RFE
       moves bits the TX39 CP0 register file does not surface. */
    s.cp0_status = (s.cp0_status & ~0xFu) | ((s.cp0_status >> 2) & 0xFu);
}
