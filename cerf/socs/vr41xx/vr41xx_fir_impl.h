#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

#include <cstdint>

namespace cerf_vr41xx_fir_detail {

/* VR41xx FIR (Fast IrDA Interface Unit): IRSR1 at block offset 0x18
   (VR4121 UM Table 27-1 p588 / VR4102 UM Table 26-1 p498). */
template <const std::string_view& Soc, uint32_t Base>
class Vr41xxFirBase : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == Soc;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        /* FRSTR / IRSR1 RTCRST=0 / after-reset=0 (VR4121 UM 27.2.1 p589, 27.2.8 p598;
           VR4102 UM 26.2.8 p507). */
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) { frstr_ = 0; irsr1_ = 0; });
    }

    uint32_t MmioBase() const override { return Base; }
    uint32_t MmioSize() const override { return 0x36u; }   /* Base .. Base+0x35 (RXFL 0x74 16-bit) */

    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t off = addr - Base;
        if (off == kOffFrstr) return frstr_;
        if (off == kOffIrsr1) return irsr1_;
        HaltUnsupportedAccess("FIR ReadHalf", addr, 0);
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        const uint32_t off = addr - Base;
        /* FRSTR (VR4121 UM 27.2.1 p589): D0 FRST R/W (1 Reset / 0 Normal); D15:1 RFU read-0. */
        if (off == kOffFrstr) { frstr_ = value & 0x0001u; return; }
        /* IRSR1 (VR4121 UM 27.2.8 p598 / VR4102 UM 26.2.8 p507): D7 IRDA_EN, D1 IRDA_MD,
           D0 MIR_MD R/W; D15:8 + D6:2 RFU write-0/read-0. */
        if (off == kOffIrsr1) { irsr1_ = value & 0x0083u; return; }
        HaltUnsupportedAccess("FIR WriteHalf", addr, value);
    }

    uint8_t  ReadByte (uint32_t addr) override { HaltUnsupportedAccess("FIR ReadByte", addr, 0); }
    uint32_t ReadWord (uint32_t addr) override { HaltUnsupportedAccess("FIR ReadWord", addr, 0); }
    void WriteByte(uint32_t addr, uint8_t  v) override { HaltUnsupportedAccess("FIR WriteByte", addr, v); }
    void WriteWord(uint32_t addr, uint32_t v) override { HaltUnsupportedAccess("FIR WriteWord", addr, v); }

    void SaveState(StateWriter& w) override { w.Write("frstr", frstr_); w.Write("irsr1", irsr1_); }
    void RestoreState(StateReader& r) override { r.Read("frstr", frstr_); r.Read("irsr1", irsr1_); }

private:
    static constexpr uint32_t kOffFrstr = 0x00u;   /* FRSTR at Base+0x00 */
    static constexpr uint32_t kOffIrsr1 = 0x18u;   /* IRSR1 at Base+0x18 */
    uint16_t frstr_ = 0;   /* FRSTR D0 FRST */
    uint16_t irsr1_ = 0;   /* IRSR1 (IRDA_EN / IRDA_MD / MIR_MD) */
};

}  /* namespace cerf_vr41xx_fir_detail */
