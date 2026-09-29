#include "../../jit/mips/mips_cp0_emitter.h"

#include <cstdint>

#include "../../boards/board_context.h"
#include "../../socs/vr4102/vr4102_id.h"
#include "../../socs/vr4111/vr4111_id.h"
#include "../../socs/vr4121/vr4121_id.h"
#include "../../socs/vr4122/vr4122_id.h"
#include "../vr5500/vr5500_id.h"
#include "../../core/cerf_emulator.h"
#include "../../jit/mips/mips_cp0_ops.h"
#include "../../jit/mips/mips_cpu_state.h"

namespace {

class MipsCp0EmitterR4000 : public MipsCp0Emitter {
public:
    using MipsCp0Emitter::MipsCp0Emitter;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && (bd->GetSocId() == SocId::Vr4102 ||
                      bd->GetSocId() == SocId::Vr4111 ||
                      bd->GetSocId() == SocId::Vr4121 ||
                      bd->GetSocId() == SocId::Vr4122 ||
                      bd->GetSocId() == SocId::Vr5500);
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

    void* Mfc0Helper(uint32_t rd) const override {
        if (rd == MipsCp0::kCount) {
            return reinterpret_cast<void*>(&MipsCp0Ops::Mfc0CountHelper);
        }
        return nullptr;
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(MipsCp0EmitterR4000, MipsCp0Emitter);
