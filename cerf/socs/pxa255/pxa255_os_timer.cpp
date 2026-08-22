#include "../os_timer.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../pxa2xx/pxa2xx_intc.h"

namespace {

/* PXA255 ICPR Table 4-35: IS26..29 = OS Timer match 0..3. */
constexpr uint32_t kIntcOst0Bit = 26u;

class Pxa255OsTimer : public OsTimer {
public:
    using OsTimer::OsTimer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA25x;
    }

    uint32_t MmioBase() const override { return 0x40A00000u; }

protected:
    void SetMatchLevel(uint32_t level4) override {
        static_cast<Pxa2xxIntc&>(emu_.Get<IrqController>())
            .SetSourceLevel(0xFu << kIntcOst0Bit,
                            (level4 & 0xFu) << kIntcOst0Bit);
    }

    void OnResetLine() override {
        OsTimer::OnResetLine();
        ResetRegistersToZero();
    }
};

REGISTER_SERVICE(Pxa255OsTimer);

}  /* namespace */
