#include "sa1111_unit.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "../../state/state_stream.h"
#include "sa1111_gpio_port_a_sink.h"
#include "sa1111_sbi.h"
#include "sa1111_system_controller.h"

#include <algorithm>
#include <iterator>

namespace {

/* SA-1111 GPIO A/B/C (Dev Man Table 10-7, base 0x40001000), 8-bit
   ports DDR/DWR·DRR/SDR/SSR at stride 0x10. Px_DDR (§10.3.3): 1=input,
   0=output, reset 0xFF - flipping the polarity inverts every port.
   Input pins read 0 (nothing drives them). */
class Sa1111Gpio : public Sa1111Unit {
public:
    using Sa1111Unit::Sa1111Unit;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Jornada720;
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
    void PostRestore() override { asleep_ = sbi_->SleepRequested(); }

protected:
    void OnUnitReady() override {
        sbi_ = &emu_.Get<Sa1111Sbi>();
        emu_.Get<Sa1111SystemController>().RegisterClockListener([this] { OnClockChange(); });
    }

    void OnChipReset(bool held) override {
        if (!held) return;
        asleep_ = false;
        LoadResetValues();
        NotifyPortA();
    }

    uint32_t UnitReadWord(uint32_t addr) override {
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

    void UnitWriteWord(uint32_t addr, uint32_t value) override {
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
        if (port == 0) NotifyPortA();
    }

private:
    /* SA-1111 Developer's Manual §10.3.1 Px_DWR "All bits are cleared (set to zero) by a
       system reset"; §10.3.3 Px_DDR and §10.3.5 Px_SDR "All bits are set by system reset". */
    static constexpr uint32_t kDdrReset = 0xFFu;
    static constexpr uint32_t kSdrReset = 0xFFu;

    void LoadResetValues() {
        std::fill(std::begin(ddr_), std::end(ddr_), kDdrReset);
        std::fill(std::begin(dwr_), std::end(dwr_), 0u);
        std::fill(std::begin(sdr_), std::end(sdr_), kSdrReset);
        std::fill(std::begin(ssr_), std::end(ssr_), 0u);
    }

    /* §10.3.4 Px_SSR: "These bits take effect on the state of the relevant pins when the
       system goes into sleep mode"; §10.3.5 Px_SDR: "clearing a bit makes the pin an output". */
    void NotifyPortA() {
        const uint32_t levels = asleep_ ? ssr_[0] & ~sdr_[0] : dwr_[0] & ~ddr_[0];
        if (auto* sink = emu_.TryGet<Sa1111GpioPortASink>()) {
            sink->OnPortAOutputs(static_cast<uint8_t>(levels & 0xFFu));
        }
    }

    void OnClockChange() {
        const bool asleep = sbi_->SleepRequested();
        if (asleep == asleep_) return;
        asleep_ = asleep;
        NotifyPortA();
    }

    const Sa1111Sbi* sbi_ = nullptr;
    bool     asleep_ = false;
    uint32_t ddr_[3] = { kDdrReset, kDdrReset, kDdrReset };
    uint32_t dwr_[3] = {};
    uint32_t sdr_[3] = { kSdrReset, kSdrReset, kSdrReset };
    uint32_t ssr_[3] = {};
};

}  /* namespace */

REGISTER_SERVICE(Sa1111Gpio);
