#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "msm8255_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "../irq_controller.h"
#include "msm8255_gpio_banks.h"
#include "msm8255_gpio_bus.h"
#include "msm8255_gpio_pin_mux.h"

#include <cstdint>
#include <mutex>
#include <typeinfo>

namespace cerf_msm8255_gpio_detail {

/* Linux arch/arm/mach-msm gpio_hw.h under CONFIG_ARCH_MSM7X30: the GPIO banks
   are split across two windows, MSM_GPIO1_REG and MSM_GPIO2_REG, each serving
   its own subset of every register family. */
template <uint32_t kBase, uint32_t kSize, uint32_t kBankCount,
          const Msm8255GpioBank (&kBanks)[kBankCount], uint32_t kMuxSelectOff,
          uint32_t kMuxConfigOff, int kGroupVicLine>
class Msm8255GpioWindowBase : public Peripheral, public Msm8255GpioWindow {
    static_assert(Msm8255GpioBanksAddressablePins(kBanks, kBankCount),
                  "every gpio bank must name an ordered range of at most 32 "
                  "pins that the controller's pin count addresses");

public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Msm8255;
    }

    void OnReady() override {
        emu_.Get<Msm8255GpioBus>().RegisterWindow(this);
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            banks_.Reset();
            mux_.Reset();
            emu_.Get<Msm8255GpioBus>().RedriveOwnedPins(this);
            UpdateIrqLine();
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    bool OwnsGpioPin(uint32_t pin) const override {
        return banks_.OwnsPin(pin);
    }

    void SetGpioInputPin(uint32_t pin, bool high) override {
        std::lock_guard<std::mutex> lk(irq_mtx_);
        if (!banks_.SetPinLevel(pin, high)) {
            emu_.Get<Fatal>().Die(
                "Peripheral '%s': gpio %u was routed here but no bank of this "
                "window carries it", typeid(*this).name(), pin);
        }
        UpdateIrqLineLocked();
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    void PostRestore() override { UpdateIrqLine(); }

    uint32_t ReadWord(uint32_t addr) override {
        uint32_t value = 0;
        if (banks_.Read(addr - kBase, value)) return value;
        HaltUnsupportedAccess("ReadWord", addr, 0u);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - kBase;

        uint32_t pins = 0;
        Msm8255GpioAccess bank;
        {
            std::lock_guard<std::mutex> lk(irq_mtx_);
            bank = banks_.Write(off, value, pins);
            if (bank == Msm8255GpioAccess::Served) {
                UpdateIrqLineLocked();
                return;
            }
        }
        if (bank == Msm8255GpioAccess::PinsAbsent) {
            emu_.Get<Fatal>().Die(
                "Peripheral '%s': the 0x%08X written to +0x%03X drives pins "
                "outside the 0x%08X that register has",
                typeid(*this).name(), value, off, pins);
        }

        uint32_t bad = 0;
        switch (mux_.Write(off, value, bad)) {
        case Msm8255GpioMuxAccess::Served:
            return;
        case Msm8255GpioMuxAccess::PinAbsent:
            emu_.Get<Fatal>().Die(
                "Peripheral '%s': +0x%03X selected gpio %u, which is not one "
                "this window serves", typeid(*this).name(), off, bad);
        case Msm8255GpioMuxAccess::ConfigBitsAbsent:
            emu_.Get<Fatal>().Die(
                "Peripheral '%s': the 0x%08X written to +0x%03X sets bits "
                "outside the 0x%03X the pull, function and drive fields "
                "occupy", typeid(*this).name(), bad, off, MuxType::kConfigMask);
        case Msm8255GpioMuxAccess::DriveUndefined:
            emu_.Get<Fatal>().Die(
                "Peripheral '%s': the 0x%08X written to +0x%03X selects drive "
                "strength %u, and only 0 through %u are named",
                typeid(*this).name(), bad, off,
                (bad >> MuxType::kDriveShift) & MuxType::kDriveFieldMask,
                MuxType::kDriveNamedMax);
        case Msm8255GpioMuxAccess::NoPinSelected:
            emu_.Get<Fatal>().Die(
                "Peripheral '%s': +0x%03X was written before +0x%03X selected "
                "a gpio", typeid(*this).name(), off, kMuxSelectOff);
        case Msm8255GpioMuxAccess::NotMine:
            break;
        }

        HaltUnsupportedAccess("WriteWord", addr, value);
    }

    void SaveState(StateWriter& w) override {
        banks_.Save(w);
        mux_.Save(w);
    }

    void RestoreState(StateReader& r) override {
        uint32_t bad_off   = 0;
        uint32_t bad_value = 0;
        if (!banks_.Restore(r, bad_off, bad_value)) {
            r.Reject(
                "Peripheral '%s': restored state at +0x%03X value 0x%08X "
                "carries pins that bank does not have",
                typeid(*this).name(), bad_off, bad_value);
        }

        uint32_t bad = 0;
        switch (mux_.Restore(r, bad)) {
        case Msm8255GpioMuxAccess::Served:
            return;
        case Msm8255GpioMuxAccess::PinAbsent:
            r.Reject(
                "Peripheral '%s': restored pin-mux state selects gpio %u, "
                "which is not one this window serves",
                typeid(*this).name(), bad);
        case Msm8255GpioMuxAccess::ConfigBitsAbsent:
            r.Reject(
                "Peripheral '%s': restored pin-mux config 0x%08X sets bits "
                "outside the 0x%03X the pull, function and drive fields "
                "occupy", typeid(*this).name(), bad, MuxType::kConfigMask);
        case Msm8255GpioMuxAccess::DriveUndefined:
            r.Reject(
                "Peripheral '%s': restored pin-mux config 0x%08X selects drive "
                "strength %u, and only 0 through %u are named",
                typeid(*this).name(), bad,
                (bad >> MuxType::kDriveShift) & MuxType::kDriveFieldMask,
                MuxType::kDriveNamedMax);
        case Msm8255GpioMuxAccess::NoPinSelected:
        case Msm8255GpioMuxAccess::NotMine:
            emu_.Get<Fatal>().Die(
                "Peripheral '%s': restoring the pin mux reported a state its "
                "reader cannot produce", typeid(*this).name());
        }
    }

private:
    void UpdateIrqLine() {
        std::lock_guard<std::mutex> lk(irq_mtx_);
        UpdateIrqLineLocked();
    }

    void UpdateIrqLineLocked() {
        auto& vic = emu_.Get<IrqController>();
        if (banks_.AnyPending()) {
            vic.AssertIrq(kGroupVicLine);
        } else {
            vic.DeAssertIrq(kGroupVicLine);
        }
    }

    std::mutex irq_mtx_;

    using MuxType = Msm8255GpioPinMux<kMuxSelectOff, kMuxConfigOff, kBankCount>;

    Msm8255GpioBanks<kBankCount> banks_{kBanks};
    MuxType                      mux_{banks_};
};

}
