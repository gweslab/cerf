#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <array>
#include <cstdint>

/* i.MX51 Keypad Port (KPP), MCIMX51RM Ch.43, base 0x73F94000 (Table 2-1).
   Named (not anonymous) so the Ford board can drive its HW_REV strap onto the
   KPDR input pins via SetInputPin. */
class Imx51Kpp : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx51;
    }
    void OnReady() override {
        regs_[kKpsrOff >> 1] = kKpsrReset;
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    /* A board device drives an external strap level onto a KPDR input pin
       (KDDR=0), read back through KPDR per RM 43.4.3.4 (input bits return the
       external level). Undriven input pins stay 0. */
    void SetInputPin(uint32_t pin, bool level) {
        if (level) input_level_ |=  static_cast<uint16_t>(1u << pin);
        else       input_level_ &= static_cast<uint16_t>(~(1u << pin));
    }

    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t idx = (addr - kBase) >> 1;
        /* KPDR read = pin state (RM 43.4.3.4): output bits (KDDR=1) read the
           driven latch, input bits (KDDR=0) read the external level (a board
           strap via SetInputPin, else 0). */
        if (idx == (kKpdrOff >> 1)) {
            const uint16_t kddr = regs_[kKddrOff >> 1];
            return static_cast<uint16_t>((regs_[idx] & kddr) |
                                         (input_level_ & static_cast<uint16_t>(~kddr)));
        }
        return regs_[idx];
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        regs_[(addr - kBase) >> 1] = value;
    }

    /* JIT-thread-only register file (no worker thread). input_level_ is
       board-driven state; serialize it symmetrically (build-specific image). */
    void SaveState(StateWriter& w) override {
        w.WriteBytes("regs", regs_.data(), sizeof(regs_));
        w.Write("input_level", input_level_);
    }
    void RestoreState(StateReader& r) override {
        r.ReadBytes("regs", regs_.data(), sizeof(regs_));
        r.Read("input_level", input_level_);
    }

private:
    static constexpr uint32_t kBase     = 0x73F94000u;
    static constexpr uint32_t kSize     = 0x00004000u;   /* AIPS-1 16 KB slot */
    static constexpr uint32_t kKpsrOff  = 0x2u;          /* Table 43-3 */
    static constexpr uint32_t kKddrOff  = 0x4u;          /* Table 43-3: 1=output, 0=input */
    static constexpr uint32_t kKpdrOff  = 0x6u;          /* Table 43-3 */
    static constexpr uint16_t kKpsrReset = 0x0400u;      /* Table 43-3 KPSR reset value */

    std::array<uint16_t, kSize / 2> regs_{};
    uint16_t input_level_ = 0;   /* board-driven external input pin levels */
};
