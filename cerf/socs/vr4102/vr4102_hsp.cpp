#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "vr4102_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

#include <cstdint>

namespace {

/* VR4102 HSP (MODEM Interface Unit), I/O-1 0x0C000020-0x0C000029 (UM ch.25,
   Table 25-1): software-modem index/data interface to an external PCT288I codec. */
constexpr uint32_t kBase        = 0x0C000020u;
constexpr uint32_t kSize        = 0x0Au;   /* 0x0C000020-0x0C000029 */
constexpr uint32_t kOffInit     = 0x00u;   /* HSPINIT   0x0C000020 R/W (UM 25.2.1) */
constexpr uint32_t kOffData     = 0x02u;   /* HSPDATA   0x0C000022 (UM 25.2.2)      */
constexpr uint32_t kOffIndex    = 0x04u;   /* HSPINDEX  0x0C000024 W  (UM 25.2.2)   */
constexpr uint32_t kOffPctel    = 0x09u;   /* HSPPCTEL  0x0C000029 W  (UM 25.2.4)   */

/* HSPINIT writable bits (UM 25.2.1 p484): D4 OPD, D3 AFESEL, D2 BYTE, D1 BSC,
   D0 HSPRST; D[15:5] reserved read 0. HSPRST (D0=1) resets the HSP unit. */
constexpr uint16_t kInitMask    = 0x001Fu;
constexpr uint16_t kInitHsprst  = 0x0001u;

class Vr4102Hsp : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Vr4102;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        /* HSPINIT RTCRST and Other-resets rows are 0 (UM 25.2.1, p484). */
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) { init_ = 0; });
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint16_t ReadHalf(uint32_t addr) override {
        if (addr - kBase == kOffInit) return init_ & kInitMask;
        /* HSPDATA read = HSPRxData/HSPSTS from the PCT288I; HSPINDEX is W-only. */
        HaltUnsupportedAccess("HSP ReadHalf", addr, 0);
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        switch (addr - kBase) {
            case kOffInit:
                init_ = value & kInitMask;
                if (value & kInitHsprst) init_ = 0;   /* HSPRST: unit reset */
                return;
            /* HSPINDEX / HSPDATA program the PCT288I over the HSP serial interface;
               CERF models no codec, and every codec read is FATAL-first below. */
            case kOffIndex:
            case kOffData:
                return;
            default: HaltUnsupportedAccess("HSP WriteHalf", addr, value);
        }
    }

    void WriteByte(uint32_t addr, uint8_t value) override {
        /* HSPPCTEL signature-port write (VR4102 HSP-unit unlock input, UM 25.2.4);
           the paired HSPPCS read is FATAL-first (ReadByte). */
        if (addr - kBase == kOffPctel) return;
        HaltUnsupportedAccess("HSP WriteByte", addr, value);
    }
    uint8_t  ReadByte (uint32_t addr) override { HaltUnsupportedAccess("HSP ReadByte", addr, 0); }
    uint32_t ReadWord (uint32_t addr) override { HaltUnsupportedAccess("HSP ReadWord", addr, 0); }
    void WriteWord(uint32_t addr, uint32_t v) override { HaltUnsupportedAccess("HSP WriteWord", addr, v); }

    void SaveState(StateWriter& w) override { w.Write("init", init_); }
    void RestoreState(StateReader& r) override { r.Read("init", init_); }

private:
    uint16_t init_ = 0;   /* HSPINIT (reset 0, UM 25.2.1) */
};

}  /* namespace */

REGISTER_SERVICE(Vr4102Hsp);
