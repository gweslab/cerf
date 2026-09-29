#include "../../jit/mips/mips_cp0_emitter.h"

#include <cstddef>
#include <cstdint>

#include "../../boards/board_context.h"
#include "../../socs/pr31x00/pr31500_id.h"
#include "../../socs/pr31x00/pr31700_id.h"
#include "../../core/cerf_emulator.h"
#include "../../jit/mips/mips_cp0_ops.h"
#include "../../jit/mips/mips_cpu_state.h"
#include "../../jit/mips/mips_translation_cache.h"
#include "tx39_config_register.h"

namespace {

/* TX39 CP0 register numbers (TMPR39xx-um Table 2-1). */
namespace Tx39Cp0 {
    constexpr uint32_t kIndex    = 0;
    constexpr uint32_t kRandom   = 1;
    constexpr uint32_t kEntryLo  = 2;
    constexpr uint32_t kConfig   = 3;
    constexpr uint32_t kContext  = 4;
    constexpr uint32_t kBadVAddr = 8;
    constexpr uint32_t kEntryHi  = 10;
    constexpr uint32_t kStatus   = 12;
    constexpr uint32_t kCause    = 13;
    constexpr uint32_t kEPC      = 14;
    constexpr uint32_t kPRId     = 15;
}

/* EntryHi (CP0 r10): VPN<31:12> PID<11:6>, reserved <5:0> "ignores writes,
   returns zero when read" (TMPR3911.pdf Fig 3.3.6). A PID change switches the
   address space, so the VA jump cache is dropped. */
constexpr uint32_t kEntryHiVpnMask = 0xFFFFF000u;
constexpr uint32_t kEntryHiPidMask = 0x00000FC0u;

void __fastcall Mtc0EntryHiR3000(uint32_t value, MipsCp0Ops* ops) {
    MipsCpuState& s = *ops->CpuState();
    const uint32_t old = s.cp0_entryhi;
    const uint32_t val = value & (kEntryHiVpnMask | kEntryHiPidMask);
    s.cp0_entryhi = val;
    if ((old & kEntryHiPidMask) != (val & kEntryHiPidMask)) {
        ops->Cache()->ContextSwitchFlush();
    }
}

class MipsCp0EmitterR3000 : public MipsCp0Emitter {
public:
    using MipsCp0Emitter::MipsCp0Emitter;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        if (!bd) return false;
        const std::string_view soc = bd->GetSocId();
        return soc == SocId::Pr31500 || soc == SocId::Pr31700;
    }

protected:
    int32_t RegOffset(uint32_t rd) const override {
        switch (rd) {
            case Tx39Cp0::kIndex:    return static_cast<int32_t>(offsetof(MipsCpuState, cp0_index));
            case Tx39Cp0::kRandom:   return static_cast<int32_t>(offsetof(MipsCpuState, cp0_random));
            case Tx39Cp0::kEntryLo:  return static_cast<int32_t>(offsetof(MipsCpuState, cp0_entrylo0));
            case Tx39Cp0::kConfig:   return static_cast<int32_t>(offsetof(MipsCpuState, cp0_config));
            case Tx39Cp0::kContext:  return static_cast<int32_t>(offsetof(MipsCpuState, cp0_context));
            case Tx39Cp0::kBadVAddr: return static_cast<int32_t>(offsetof(MipsCpuState, cp0_badvaddr));
            case Tx39Cp0::kEntryHi:  return static_cast<int32_t>(offsetof(MipsCpuState, cp0_entryhi));
            case Tx39Cp0::kStatus:   return static_cast<int32_t>(offsetof(MipsCpuState, cp0_status));
            case Tx39Cp0::kCause:    return static_cast<int32_t>(offsetof(MipsCpuState, cp0_cause));
            case Tx39Cp0::kEPC:      return static_cast<int32_t>(offsetof(MipsCpuState, cp0_epc));
            case Tx39Cp0::kPRId:     return static_cast<int32_t>(offsetof(MipsCpuState, cp0_prid));
            default:                 return -1;
        }
    }

    void* Mtc0Helper(uint32_t rd) const override {
        if (rd == Tx39Cp0::kEntryHi) {
            return reinterpret_cast<void*>(&Mtc0EntryHiR3000);
        }
        if (rd == Tx39Cp0::kConfig) {
            return reinterpret_cast<void*>(&Tx39ConfigRegister::Mtc0Helper);
        }
        return nullptr;
    }

    void* Mtc0HelperContext(uint32_t rd, MipsBlockContext* ctx) const override {
        if (rd == Tx39Cp0::kConfig) return &emu_.Get<Tx39ConfigRegister>();
        return MipsCp0Emitter::Mtc0HelperContext(rd, ctx);
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(MipsCp0EmitterR3000, MipsCp0Emitter);
