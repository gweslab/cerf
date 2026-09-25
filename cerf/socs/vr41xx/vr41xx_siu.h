#pragma once

#include "../../peripherals/uart16550/uart16550.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../host/host_widget_registry.h"
#include "../../peripherals/serial/serial_cradle.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "vr41xx_giu.h"
#include "vr41xx_icu.h"
#include "vr41xx_serial_wiring.h"

#include <cstdint>
#include <memory>
#include <optional>

/* VR41xx on-chip SIU: NS16550-compatible UART at base 0x0C000000, byte-addressed (SCR at
   0x0C000007); interrupt is SYSINT1 D9 SIUINTR (VR4121 UM 15.2.1 p373 / VR4102 UM 14.2.1
   p295). Registers 0x00-0x08 chip-identical (VR4121 UM Table 25-1 p553 == VR4102 UM
   Table 24-1 p461); VR4102 stops at 0x08, VR4121 adds 0x09 SIURESET / 0x0A SIUCSEL. */
class Vr41xxSiu : public Uart16550 {
public:
    explicit Vr41xxSiu(CerfEmulator& emu)
        : Uart16550(emu, Config{/*ier_mask=*/0x0Fu,
                                /*irq_gate_mcr=*/0u,
                                /*irq_gate_ier=*/0u}) {}

    uint32_t MmioBase() const override { return 0x0C000000u; }
    uint32_t MmioSize() const override { return 0x20u; }   /* SIU block; HSP follows at +0x20 */

    void OnReady() override {
        Uart16550::OnReady();

        /* The SIU is an on-chip unit, so the reset line clears it (UM 7.1.4: a reset
           "initializes the entire internal state except for the RTC timer and the PMU").
           SIUIRSEL's RTCRST and After-reset rows are both 0 (VR4121 UM 25.2.13 p568 /
           VR4102 UM 24.2.13 p478). */
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            Serial16550::ResetRegisters();
            irsel_ = 0;
            ResetChip();
        });
        emu_.Get<GuestCpuReset>().RegisterResetReleaseListener([this] {
            ResendEndpointInputs();
        });

        auto* wiring = emu_.TryGet<Vr41xxSerialWiring>();
        if (!wiring) return;
        modem_ = wiring->ForSiu();
        if (!modem_) return;

        /* GIU pins reset low and carrier is asserted low, so an undriven DCD pin reads as
           carrier already present. */
        SetModemInputs(false, false, false, false);

        cradle_ = std::make_unique<SerialCradle>(emu_, *this, modem_->label);
        SetActivityWidget(cradle_.get());
        emu_.Get<HostWidgetRegistry>().Register(cradle_.get());
        LOG(Periph, "[UART] SIU attached as serial endpoint line '%ls'\n",
            modem_->label.c_str());
    }

    void OnShutdown() override {
        if (cradle_) cradle_->OnShutdown();
    }

    /* A board's carrier pin is asserted low, so the level driven onto the GIU is the
       inverse of the endpoint's DCD. */
    void SetModemInputs(bool cts, bool dsr, bool ri, bool dcd) override {
        if (modem_ && modem_->dcd_giu_pin >= 0) {
            emu_.Get<Vr41xxGiu>().SetPinLevel(modem_->dcd_giu_pin, !dcd);
            Uart16550::SetModemInputs(cts, dsr, ri, false);
            return;
        }
        Uart16550::SetModemInputs(cts, dsr, ri, dcd);
    }

protected:
    uint32_t    RegStride() const override { return 1u; }
    const char* Name()      const override { return "SIU"; }

    void SetInterruptLine(bool pending) override {
        emu_.Get<Vr41xxIcu>().SetSysint1Source(kSiuIntr, pending);
    }

    /* 0x08 SIUIRSEL D5:0 R/W (VR4121 UM 25.2.13 p568 / VR4102 UM 24.2.13 p478); D7:6 RFU. */
    uint32_t ReadExtReg(uint32_t idx) override {
        if (idx == 8u) return irsel_;
        return ReadChipExtReg(idx);
    }
    void WriteExtReg(uint32_t idx, uint32_t value) override {
        if (idx == 8u) { irsel_ = static_cast<uint8_t>(value & 0x3Fu); return; }
        WriteChipExtReg(idx, value);
    }

    /* SIU registers at index >= 9. VR4102 has one undocumented register there; VR4121 has
       SIURESET (0x09) + SIUCSEL (0x0A). Default: unsupported access halts. */
    virtual uint32_t ReadChipExtReg(uint32_t idx)                { return Uart16550::ReadExtReg(idx); }
    virtual void     WriteChipExtReg(uint32_t idx, uint32_t val) { Uart16550::WriteExtReg(idx, val); }
    virtual void     ResetChip()                      = 0;
    virtual void     SaveChipState(StateWriter& w)    = 0;
    virtual void     RestoreChipState(StateReader& r) = 0;

    void SaveState(StateWriter& w) override {
        Uart16550::SaveState(w); w.Write("irsel", irsel_); SaveChipState(w);
        if (cradle_) cradle_->SaveCradleState(w);
    }
    void RestoreState(StateReader& r) override {
        Uart16550::RestoreState(r); r.Read("irsel", irsel_); RestoreChipState(r);
        if (cradle_) cradle_->RestoreCradleState(r);
    }
    void PostRestore() override {
        Uart16550::PostRestore();
        if (cradle_) cradle_->PostRestore();
    }

private:
    static constexpr uint16_t kSiuIntr = 1u << 9;   /* SYSINT1 D9 SIUINTR */
    uint8_t irsel_ = 0;   /* SIU 0x08 SIUIRSEL */

    std::optional<Vr41xxSerialModem> modem_;
    std::unique_ptr<SerialCradle>    cradle_;
};
