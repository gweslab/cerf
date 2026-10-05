#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../guest_cpu_reset.h"
#include "pxa255_i2s_stream.h"
#include "pxa255_id.h"

#include <cstdint>

namespace {

/* Intel PXA255 Developer's Manual Table 14-3 (page 14-9) SACR0: ENB 0, BCKD 2, RST 3, EFWR 4, STRF 5,
   TFTH 11:8, RFTH 15:12; Table 14-6 (page 14-11) SACR1: AMSL 0, DREC 3, DRPL 4, ENLBF 5. */
constexpr uint32_t kSacr0Enb = 1u << 0, kSacr0Bckd = 1u << 2, kSacr0Rst = 1u << 3, kSacr0Efwr = 1u << 4;
constexpr uint32_t kSacr0Defined = 0xFF3Du;
constexpr uint32_t kSacr1Enlbf   = 1u << 5;

/* Intel PXA255 Developer's Manual Table 14-8 (page 14-13): valid SADIV 0x0C, 0x0D, 0x1A, 0x24, 0x34,
   0x48. */
bool ValidSadiv(uint32_t v) {
    return v == 0x0Cu || v == 0x0Du || v == 0x1Au || v == 0x24u || v == 0x34u || v == 0x48u;
}

class Pxa255I2s : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Pxa255;
    }

    void OnReady() override {
        clock_  = &emu_.Get<GuestCycleClock>();
        stream_ = &emu_.Get<Pxa255I2sStream>();
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) { stream_->ResetLine(); });
    }

    uint32_t MmioBase() const override { return 0x40400000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord(uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override { stream_->Save(w); }
    void RestoreState(StateReader& r) override { stream_->Restore(r); }

private:
    enum : uint32_t {
        kSACR0 = 0x00u, kSACR1 = 0x04u, kSASR0 = 0x0Cu, kSAIMR = 0x14u, kSAICR = 0x18u,
        kSADIV = 0x60u, kSADR = 0x80u,
    };

    void WriteSacr0(uint64_t now, uint32_t value);
    void WriteSacr1(uint64_t now, uint32_t value);
    void WriteSadiv(uint32_t value);

    GuestCycleClock* clock_  = nullptr;
    Pxa255I2sStream* stream_ = nullptr;
};

uint32_t Pxa255I2s::ReadWord(uint32_t addr) {
    switch (addr - MmioBase()) {
    case kSACR0: return stream_->Sacr0();
    case kSACR1: return stream_->Sacr1();
    case kSAIMR: return 0u;
    case kSADIV: return stream_->Sadiv();
    case kSADR:  return stream_->ReadData(clock_->Cycles());
    case kSASR0:
        emu_.Get<Fatal>().Die("Pxa255I2s: SASR0 read; the status register is not modelled");
    case kSAICR:
        emu_.Get<Fatal>().Die("Pxa255I2s: read of the write-only SAICR");
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa255I2s::WriteWord(uint32_t addr, uint32_t value) {
    const uint64_t now = clock_->Cycles();
    switch (addr - MmioBase()) {
    case kSACR0: WriteSacr0(now, value); return;
    case kSACR1: WriteSacr1(now, value); return;
    case kSADIV: WriteSadiv(value); return;
    case kSADR:  stream_->WriteData(now, value); return;
    case kSAIMR:
        if (value != 0u) {
            emu_.Get<Fatal>().Die("Pxa255I2s: SAIMR 0x%08X enables an I2S interrupt; not modelled", value);
        }
        return;
    case kSAICR:
        emu_.Get<Fatal>().Die("Pxa255I2s: SAICR write 0x%08X; the status register is not modelled", value);
    case kSASR0:
        emu_.Get<Fatal>().Die("Pxa255I2s: write 0x%08X to the read-only SASR0", value);
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Pxa255I2s::WriteSacr0(uint64_t now, uint32_t value) {
    const uint32_t v = value & kSacr0Defined;
    if (stream_->Enabled()) {
        if (v != stream_->Sacr0()) {
            emu_.Get<Fatal>().Die("Pxa255I2s: SACR0 0x%08X changes the control of an enabled I2S link "
                                  "(0x%08X); not modelled", value, stream_->Sacr0());
        }
        return;
    }
    if ((v & (kSacr0Rst | kSacr0Efwr)) != 0u) {
        emu_.Get<Fatal>().Die("Pxa255I2s: SACR0 0x%08X sets RST or EFWR; not modelled", value);
    }
    if ((v & kSacr0Enb) == 0u) {
        stream_->StoreSacr0(v);
        return;
    }
    /* Intel PXA255 Developer's Manual Table 14-3 (page 14-9) BCKD: "0 = Input. BITCLK driven by an
       external source." */
    if ((v & kSacr0Bckd) == 0u) {
        emu_.Get<Fatal>().Die("Pxa255I2s: SACR0 0x%08X enables the link with an external BITCLK; "
                              "not modelled", value);
    }
    stream_->Enable(now, v);
}

void Pxa255I2s::WriteSacr1(uint64_t now, uint32_t value) {
    if ((value & kSacr1Enlbf) != 0u) {
        emu_.Get<Fatal>().Die("Pxa255I2s: SACR1 0x%08X enables the loop-back function; not modelled",
                              value);
    }
    stream_->WriteSacr1(now, value);
}

/* Intel PXA255 Developer's Manual section 14.6.4 (page 14-13): "Setting this register to values other
   than those shown in Section 14.2 is not allowed and will cause unpredictable activity." */
void Pxa255I2s::WriteSadiv(uint32_t value) {
    if (!ValidSadiv(value) || stream_->Enabled()) {
        emu_.Get<Fatal>().Die("Pxa255I2s: SADIV write 0x%08X (link %s); not modelled", value,
                              stream_->Enabled() ? "enabled" : "disabled");
    }
    stream_->StoreSadiv(value);
}

}  // namespace

REGISTER_SERVICE(Pxa255I2s);
