#include "../os_timer.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "pxa255_intc.h"

namespace {

/* PXA255 ICPR Table 4-35: IS26..29 = OS Timer match 0..3. */
constexpr uint32_t kIntcOst0Bit = 26u;

class Pxa255OsTimer : public OsTimer {
public:
    using OsTimer::OsTimer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::PXA25x;
    }

    uint32_t MmioBase() const override { return 0x40A00000u; }

protected:
    void AssertMatch(int n) override {
        emu_.Get<Pxa255Intc>().AssertSource(kIntcOst0Bit + n);
    }
    void DeassertMatch(int n) override {
        emu_.Get<Pxa255Intc>().DeassertSource(kIntcOst0Bit + n);
    }
};

REGISTER_SERVICE(Pxa255OsTimer);

}  /* namespace */
