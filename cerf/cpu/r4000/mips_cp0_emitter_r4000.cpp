#include "../../jit/mips/mips_cp0_emitter.h"

#include <cstdint>

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../jit/mips/mips_cp0_ops.h"
#include "../../jit/mips/mips_cpu_state.h"

namespace {

class MipsCp0EmitterR4000 : public MipsCp0Emitter {
public:
    using MipsCp0Emitter::MipsCp0Emitter;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && (bd->GetSoc() == SocFamily::VR4102 ||
                      bd->GetSoc() == SocFamily::VR4111 ||
                      bd->GetSoc() == SocFamily::VR4121 ||
                      bd->GetSoc() == SocFamily::VR4122 ||
                      bd->GetSoc() == SocFamily::VR5500);
    }

protected:
    int32_t RegOffset(uint32_t rd) const override { return Cp0RegOffset(rd); }

    void* Mtc0Helper(uint32_t rd) const override {
        if (rd == MipsCp0::kCount) {
            return reinterpret_cast<void*>(&MipsCp0Ops::Mtc0CountHelper);
        }
        if (rd == MipsCp0::kCompare) {
            return reinterpret_cast<void*>(&MipsCp0Ops::Mtc0CompareHelper);
        }
        if (rd == MipsCp0::kEntryHi) {
            return reinterpret_cast<void*>(&MipsCp0Ops::Mtc0EntryHiHelper);
        }
        return nullptr;
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(MipsCp0EmitterR4000, MipsCp0Emitter);
