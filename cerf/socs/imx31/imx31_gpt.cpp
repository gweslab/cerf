#include "../freescale_gpt_impl.h"

#include "imx31_avic.h"
#include "imx31_id.h"

namespace {

using cerf_freescale_gpt_detail::GptClockInput;

/* MCIMX31RM Table 34-6: SWR keeps EN, ENMOD, STOPEN, DOZEN, WAITEN and DBGEN;
   CLKSRC 000 none, 001 ipg_clk, 010 ipg_clk_highfreq, 100 ipg_clk_32k, others
   not defined. Table 34-6 ENMOD: EN=0 resets the prescaler counter. */
struct Imx31GptTraits {
    static constexpr uint32_t kCrSwrKeep                  = 0x3Fu;
    static constexpr uint32_t kDozeEnable                 = cerf_freescale_gpt_detail::kGptcrDozen;
    static constexpr bool     kPrescalerHoldsWhenDisabled = false;

    static constexpr GptClockInput Clksrc(uint32_t v) {
        switch (v) {
            case 0u: return GptClockInput::kNone;
            case 1u: return GptClockInput::kIpg;
            case 2u: return GptClockInput::kHighfreq;
            case 4u: return GptClockInput::kLowfreq;
            default: return GptClockInput::kUndefined;
        }
    }
};

/* MCIMX31RM Table 2-3: GPT is AVIC source 29. */
class Imx31Gpt
    : public cerf_freescale_gpt_detail::FreescaleGptBase<0x53F90000u, SocId::Imx31,
                                                          Imx31GptTraits> {
    using FreescaleGptBase::FreescaleGptBase;
    void AssertIrqLine()   override { emu_.Get<Imx31Avic>().AssertSource(29u); }
    void DeassertIrqLine() override { emu_.Get<Imx31Avic>().DeassertSource(29u); }
};

}

REGISTER_SERVICE(Imx31Gpt);
