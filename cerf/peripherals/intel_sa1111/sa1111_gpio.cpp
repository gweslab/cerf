#include "../peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "../peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "sa1111_gpio_port_a_sink.h"

namespace {

/* SA-1111 GPIO A/B/C (Dev Man Table 10-7, base 0x40001000), 8-bit
   ports DDR/DWR·DRR/SDR/SSR at stride 0x10. Px_DDR (§10.3.3): 1=input,
   0=output, reset 0xFF - flipping the polarity inverts every port.
   Input pins read 0 (nothing drives them). */
class Sa1111Gpio : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Jornada720;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x40001000u; }
    uint32_t MmioSize() const override { return 0x00000200u; }

    void SaveState(StateWriter& w) override {
        w.WriteBytes("ddr", ddr_, sizeof(ddr_));
        w.WriteBytes("dwr", dwr_, sizeof(dwr_));
        w.WriteBytes("sdr", sdr_, sizeof(sdr_));
        w.WriteBytes("ssr", ssr_, sizeof(ssr_));
    }
    void RestoreState(StateReader& r) override {
        r.ReadBytes("ddr", ddr_, sizeof(ddr_));
        r.ReadBytes("dwr", dwr_, sizeof(dwr_));
        r.ReadBytes("sdr", sdr_, sizeof(sdr_));
        r.ReadBytes("ssr", ssr_, sizeof(ssr_));
    }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (off >= 0x30u || (off & 3u)) HaltUnsupportedAccess("ReadWord", addr, 0);
        const uint32_t port = off >> 4, reg = (off >> 2) & 3u;
        switch (reg) {
            case 0: return ddr_[port];
            case 1: return dwr_[port] & ~ddr_[port] & 0xFFu;  /* DRR: output pins read their latch. */
            case 2: return sdr_[port];
            case 3: return ssr_[port];
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        if (off >= 0x30u || (off & 3u)) HaltUnsupportedAccess("WriteWord", addr, value);
        const uint32_t port = off >> 4, reg = (off >> 2) & 3u, v = value & 0xFFu;
        switch (reg) {
            case 0: ddr_[port] = v; break;
            case 1: dwr_[port] = v; break;
            case 2: sdr_[port] = v; return;
            case 3: ssr_[port] = v; return;
            default: HaltUnsupportedAccess("WriteWord", addr, value);
        }
        if (port == 0) {
            if (auto* sink = emu_.TryGet<Sa1111GpioPortASink>()) {
                sink->OnPortAOutputs(
                    static_cast<uint8_t>(dwr_[0] & ~ddr_[0] & 0xFFu));
            }
        }
    }

private:
    uint32_t ddr_[3] = { 0xFFu, 0xFFu, 0xFFu };  /* reset: all input (§10.3.3). */
    uint32_t dwr_[3] = {};
    uint32_t sdr_[3] = {};
    uint32_t ssr_[3] = {};
};

}  /* namespace */

REGISTER_SERVICE(Sa1111Gpio);
