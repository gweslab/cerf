#pragma once

#include <cstdint>

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/service.h"
#include "../../socs/cycle_anchored_counter.h"
#include "../guest_cycle_clock.h"

struct MipsCpuState;

class MipsCoreClock;
class MipsMmu;
class MipsProcessorConfig;
class MipsTranslationCache;

class MipsCp0Ops : public Service {
public:
    using Service::Service;

    void OnReady() override;
    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetCpuArch() == CpuArch::Mips;
    }

    void OnCpuReset();
    void SaveCount();
    void OnCpuStateRestored();

    static void __fastcall TlbwiHelper(MipsCp0Ops* ops);
    static void __fastcall TlbwrHelper(MipsCp0Ops* ops);
    static void __fastcall TlbpHelper(MipsCp0Ops* ops);
    static void __fastcall TlbrHelper(MipsCp0Ops* ops);

    static uint32_t __fastcall Mfc0RandomHelper(MipsCp0Ops* ops);
    static uint32_t __fastcall Mfc0CountHelper(MipsCp0Ops* ops);

    static void __fastcall Mtc0CountHelper(uint32_t value, MipsCp0Ops* ops);
    static void __fastcall Mtc0CompareHelper(uint32_t value, MipsCp0Ops* ops);

    static void __fastcall Mtc0EntryHiHelper(uint32_t value, MipsCp0Ops* ops);

    static void __fastcall EretHelper(MipsCp0Ops* ops);
    static void __fastcall RfeHelper(MipsCp0Ops* ops);

    MipsCpuState*         CpuState() { return cpu_state_; }
    MipsTranslationCache* Cache()    { return cache_; }

private:
    void AnchorSavedCount();
    void SetCountRatio();
    void ArmCompare(uint64_t now);
    void OnCompareMatch();

    MipsCpuState*           cpu_state_     = nullptr;
    MipsMmu*                mmu_           = nullptr;
    MipsTranslationCache*   cache_         = nullptr;
    MipsProcessorConfig*    config_        = nullptr;
    GuestCycleClock*        clock_         = nullptr;
    MipsCoreClock*          core_clock_    = nullptr;
    GuestCycleClock::Event* compare_event_ = nullptr;
    CycleAnchoredCounter    count_;
};
