#include "../vr41xx/vr41xx_giu_impl.h"

#include <cstdint>
#include "vr4122_id.h"

namespace {

using cerf_vr41xx_giu_detail::Vr41xxGiuBase;
using cerf_vr41xx_giu_detail::Vr41xxGiuModel;

/* VR4122 GIU (VR4131 UM U15350EJ2V0UM Table 14-2, p.256; NetBSD vripreg.h
   VR4122_GIU_ADDR): GIUIOSELL..GIUPODATL at 0x0F000140-0x0F00015E. */
constexpr Vr41xxGiuModel kModel = {
    /*base=*/0x0F000140u,
    /*size=*/0x20u,
    /*podat_l_power_on=*/0u,
    /* GIUINTSTATL: "1 is set to the corresponding INTS bit when the signal input ... meets
       the condition ... Even if the corresponding bit is set to 1, however, no interrupt
       occurs when the corresponding bit in the GIUINTENL register is set to 0" (VR4131 UM
       14.2.5, p.261). */
    /*intstat_sets_while_disabled=*/true,
    /*inten_gates_icu_input=*/true,
    /*podat_l_retained_on_reset=*/false,
    /* The VR4131 UM documents no GIUPODATH; offset 0x1E is GIUPODATL (14.2.16 p.273),
       which Vr4122Giu::ReadHalf/WriteHalf intercept before the base decodes it. */
    /*podat_h_retained_on_reset=*/false,
};

/* Table 14-2 (p.256): the VR4122/VR4131 GIU tail is GIUPODATEN (offset 0x1C) then GIUPODATL
   (offset 0x1E); the shared VR4102/4121 template decodes 0x1C as its own GIUPODATL, and its
   ReadWord/WriteWord call the private ReadHalfLocked, so a word access touching the tail
   must not reach the base. */
class Vr4122Giu : public Vr41xxGiuBase<SocId::Vr4122, kModel> {
public:
    using Vr41xxGiuBase::Vr41xxGiuBase;

    /* GIUPODATEN 0x1C D3:0 PIOEN(35:32), GIUPODATL 0x1E D3:0 PIOD(35:32) - a latch
       independent of PIOEN ("The set value can be read by reading the PIOD bit");
       RTCRST column 0, other resets retained (VR4131 UM 14.2.15 p.272 / 14.2.16
       p.273). Guest: sh 0 -> 0x15C @0x9F033A1C, sh 0 -> 0x15E @0x9F033A24. */
    void OnReady() override {
        Vr41xxGiuBase::OnReady();
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind kind) {
            if (kind == ResetLineKind::Rtc) {
                podaten_ = 0;
                podatl_  = 0;
            }
        });
    }

    uint16_t ReadHalf(uint32_t addr) override {
        switch (addr - MmioBase()) {
            case kTailPodatEn: return podaten_;
            case kTailPodatL:  return podatl_;
            default: return Vr41xxGiuBase::ReadHalf(addr);
        }
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        switch (addr - MmioBase()) {
            case kTailPodatEn:
                podaten_ = static_cast<uint16_t>(value & kPioenMask);
                return;
            case kTailPodatL:
                podatl_ = static_cast<uint16_t>(value & kPioenMask);
                return;
            default: Vr41xxGiuBase::WriteHalf(addr, value); return;
        }
    }
    uint32_t ReadWord(uint32_t addr) override {
        if (TouchesTail(addr - MmioBase())) HaltUnsupportedAccess("VR4122 GIU output-data tail", addr, 0);
        return Vr41xxGiuBase::ReadWord(addr);
    }
    void WriteWord(uint32_t addr, uint32_t value) override {
        if (TouchesTail(addr - MmioBase())) HaltUnsupportedAccess("VR4122 GIU output-data tail", addr, value);
        Vr41xxGiuBase::WriteWord(addr, value);
    }

    void SaveState(StateWriter& w) override {
        Vr41xxGiuBase::SaveState(w);
        w.Write("podaten", podaten_);
        w.Write("podatl", podatl_);
    }
    void RestoreState(StateReader& r) override {
        Vr41xxGiuBase::RestoreState(r);
        r.Read("podaten", podaten_);
        r.Read("podatl", podatl_);
    }

private:
    static bool TouchesTail(uint32_t off) { return off + 4u > 0x1Cu && off < 0x20u; }

    static constexpr uint32_t kTailPodatEn = 0x1Cu;
    static constexpr uint32_t kTailPodatL  = 0x1Eu;
    static constexpr uint16_t kPioenMask   = 0x000Fu;

    uint16_t podaten_ = 0, podatl_ = 0;
};

}  /* namespace */

REGISTER_SERVICE_AS(Vr4122Giu, Vr41xxGiu);
