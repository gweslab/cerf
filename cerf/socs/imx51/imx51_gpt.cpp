#include "../freescale_gpt_impl.h"

#include "../irq_controller.h"
#include "imx51_id.h"

namespace {

using cerf_freescale_gpt_detail::GptClockInput;

/* MCIMX51RM Table 36-5: SWR keeps EN, ENMOD, STOPEN, WAITEN and DBGEN; bit 4 is
   reserved; CLKSRC 000 no clock, 001 ipg_clk, 010 ipg_clk_highfreq, 011
   ipp_ind_clkin, 1xx ipg_clk_32k. ENMOD: EN=0 freezes the prescaler counter. */
struct Imx51GptTraits {
    static constexpr uint32_t kCrSwrKeep                  = 0x2Fu;
    static constexpr uint32_t kDozeEnable                 = 0u;
    static constexpr bool     kPrescalerHoldsWhenDisabled = true;

    static constexpr GptClockInput Clksrc(uint32_t v) {
        switch (v) {
            case 0u: return GptClockInput::kNone;
            case 1u: return GptClockInput::kIpg;
            case 2u: return GptClockInput::kHighfreq;
            case 3u: return GptClockInput::kPad;
            default: return GptClockInput::kLowfreq;
        }
    }
};

/* MCIMX51RM Table 3-2: GPT is TZIC source 39. */
class Imx51Gpt
    : public cerf_freescale_gpt_detail::FreescaleGptBase<0x73FA0000u, SocId::Imx51,
                                                          Imx51GptTraits> {
    using FreescaleGptBase::FreescaleGptBase;
    void AssertIrqLine()   override { emu_.Get<IrqController>().AssertIrq(39); }
    void DeassertIrqLine() override { emu_.Get<IrqController>().DeAssertIrq(39); }
};

}

REGISTER_SERVICE(Imx51Gpt);
