#include "../../socs/sa11xx/sa11xx_ssp_clock_input.h"

#include "../../boards/board_context.h"
#include "ipaq_gen1_id.h"
#include "../../core/cerf_emulator.h"
#include "../../socs/sa11xx/sa11xx_gpio.h"

#include <cstdint>

namespace {

/* Linux sa11xx-uda1341 driver, sa11xx_uda1341_set_audio_clock(): GPIO 13:12 "00: 12.288 MHz",
   "01: 11.2896 MHz", "10: 4.096 MHz", "11: 5.6245 MHz"; ipaq_h3600_ppc2002 wavedev.dll
   sub_F65450 sets GPIO 12 and 13 per sample rate on the same table. */
constexpr uint32_t kClkSet0 = 12u;
constexpr uint32_t kClkSet1 = 13u;
constexpr uint64_t kClockHz[4] = {12288000u, 11289600u, 4096000u, 5624500u};

class IpaqGen1SspClock : public Sa11xxSspClockInput {
public:
    using Sa11xxSspClockInput::Sa11xxSspClockInput;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::IpaqGen1;
    }

    void OnReady() override {
        gpio_ = &emu_.Get<Sa11xxGpio>();
        gpio_->RegisterOutputObserver([this](uint32_t levels, uint32_t mask, bool resync) {
            const uint32_t select = ((levels >> kClkSet0) & 0x3u) | (((mask >> kClkSet0) & 0x3u) << 2);
            if (!resync && select == select_) return;
            select_ = select;
            NotifyChange();
        });
    }

    bool Frequency(GuestCycleClock::Rate& hz) const override {
        const Sa11xxGpio::PinConfig set0 = gpio_->Pin(kClkSet0);
        const Sa11xxGpio::PinConfig set1 = gpio_->Pin(kClkSet1);
        if (!set0.output || set0.alternate || !set1.output || set1.alternate) return false;
        hz = GuestCycleClock::Rate{kClockHz[(set0.latch ? 1u : 0u) | (set1.latch ? 2u : 0u)], 1u};
        return true;
    }

private:
    Sa11xxGpio* gpio_   = nullptr;
    uint32_t    select_ = 0;
};

}

REGISTER_SERVICE_AS(IpaqGen1SspClock, Sa11xxSspClockInput);
