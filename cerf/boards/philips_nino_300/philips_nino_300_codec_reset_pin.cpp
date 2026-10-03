#include "../../peripherals/philips_ucb1200/ucb1x00_codec.h"

#include "../board_context.h"
#include "philips_nino_300_id.h"
#include "../../core/cerf_emulator.h"
#include "../../socs/pr31x00/pr31x00_io.h"

#include <cstdint>

namespace {

/* philips_nino_300 sib.dll sub_18D1824 pulses MFIODOUT bit 19 high, low, high before
   sub_18D1768 reads the codec ID. */
constexpr uint32_t kMfioCodecReset = 1u << 19;

class PhilipsNino300CodecResetPin : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::PhilipsNino300;
    }

    void OnReady() override {
        emu_.Get<Pr31x00Io>().RegisterMfioOutObserver([this](uint32_t dout, uint32_t out_mask) {
            using Pin = Ucb1x00Codec::ResetPin;
            const Pin level = (out_mask & kMfioCodecReset) == 0u ? Pin::Floating
                              : (dout & kMfioCodecReset) != 0u   ? Pin::High
                                                                 : Pin::Low;
            emu_.Get<Ucb1x00Codec>().DriveResetPin(level);
        });
    }
};

}

REGISTER_SERVICE(PhilipsNino300CodecResetPin);
