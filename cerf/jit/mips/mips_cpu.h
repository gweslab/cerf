#pragma once

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/service.h"
#include "mips_cpu_state.h"

class StateWriter;
class StateReader;

class MipsCpu : public Service {
public:
    using Service::Service;

    void OnReady() override;
    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetCpuArch() == CpuArch::Mips;
    }

    MipsCpuState* State() { return &state_; }

    void ResetState();

    /* VR4102 UM ch.27 p587 HIBERNATE: the internal and system interface clocks
       shut down, and a Cold Reset sequence exits the mode. */
    static void __fastcall HibernateHelper(uint32_t next_pc, MipsCpu* cpu);

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);

private:
    template <typename F>
    static constexpr void VisitState(MipsCpuState& s, F& field);

    MipsCpuState state_{};
};
