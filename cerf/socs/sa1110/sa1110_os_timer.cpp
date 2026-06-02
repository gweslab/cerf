#include "../os_timer.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "sa1110_intc.h"

namespace {

/* SA-1110 §9.2.1.1 Table 9-1: IP26..29 = OSMR0..3 match. */
constexpr uint32_t kIntcOst0Bit = 26u;

class Sa1110OsTimer : public OsTimer {
public:
    using OsTimer::OsTimer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::SA1110;
    }

    uint32_t MmioBase() const override { return 0x90000000u; }

protected:
    void AssertMatch(int n) override {
        emu_.Get<Sa1110Intc>().AssertSource(kIntcOst0Bit + n);
    }
    void DeassertMatch(int n) override {
        emu_.Get<Sa1110Intc>().DeassertSource(kIntcOst0Bit + n);
    }
};

REGISTER_SERVICE(Sa1110OsTimer);

}  /* namespace */
