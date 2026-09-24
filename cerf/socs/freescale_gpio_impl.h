#pragma once

#include "../peripherals/peripheral_base.h"

#include "../core/cerf_emulator.h"
#include "../boards/board_context.h"
#include "imx51/imx51_id.h"
#include "../peripherals/peripheral_dispatcher.h"
#include "../state/state_stream.h"
#include "irq_controller.h"

#include <cstdint>
#include <functional>
#include <mutex>

namespace cerf_freescale_gpio_detail {

constexpr uint32_t kGpioSize = 0x00004000u;

/* MCIMX51RM Table 35-2 / MCIMX31RM Table 5-3. EDGE_SEL (0x1C) is i.MX51-only. */
constexpr uint32_t kOffDr      = 0x00u;
constexpr uint32_t kOffGdir    = 0x04u;
constexpr uint32_t kOffPsr     = 0x08u;
constexpr uint32_t kOffIcr1    = 0x0Cu;
constexpr uint32_t kOffIcr2    = 0x10u;
constexpr uint32_t kOffImr     = 0x14u;
constexpr uint32_t kOffIsr     = 0x18u;
constexpr uint32_t kOffEdgeSel = 0x1Cu;

/* Freescale i.MX GPIO (i.MX31 MCIMX31RM Ch 5 / i.MX51 MCIMX51RM Ch 35); i.MX51 adds
   EDGE_SEL (0x1C); gated per concrete by kSoc; 32-bit access only. kIrqLow16/kIrqHigh16
   = the TZIC sources (MCIMX51RM Table 3-2) for a concrete's OR'd pin 0-15 / 16-31
   lines; -1 (default) = passive register file, interrupt path compiled out. */
template <uint32_t kBase, const std::string_view& kSoc, int kIrqLow16 = -1, int kIrqHigh16 = -1>
class FreescaleGpioBase : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == kSoc;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kGpioSize; }

    /* A board device drives an external input pin level, observed by the guest
       through PSR (the pad-input semantic documented at the PSR read below).
       Undriven pins stay 0. On an interrupt-enabled concrete a matching ICR
       edge/level (+IMR) raises the OR'd TZIC line. */
    void SetInputPin(uint32_t pin, bool level) {
        if constexpr (kIrqLow16 >= 0) {
            std::lock_guard<std::mutex> lk(irq_mu_);
            const bool prev = (input_level_ >> pin) & 1u;
            driven_mask_ |= (1u << pin);
            SetLevelBit(pin, level);
            DetectEdgeLocked(pin, prev, level);
            RecomputeIrqLocked();
        } else {
            SetLevelBit(pin, level);
        }
    }

    /* A board device that bit-bangs a protocol over GPIO pins (Ford SYNC2's
       software-I2C "HIC1:" on GPIO4.16/17, hsi2c.dll sub_C09F18D8) observes the
       guest's SCL/SDA edges through a write callback and reads the master-driven
       level via these getters; it drives the line back through SetInputPin. */
    void SetWriteObserver(std::function<void()> cb) { write_obs_ = std::move(cb); }
    bool PinIsOutput(uint32_t pin) const { return (gdir_ >> pin) & 1u; }
    bool PinOutLevel(uint32_t pin) const { return (dr_ >> pin) & 1u; }
    bool PinInputLevel(uint32_t pin) const { return (input_level_ >> pin) & 1u; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        if constexpr (kSoc == SocId::Imx51) {
            if (off == kOffEdgeSel) return edge_sel_;
        }
        switch (off) {
            /* A DR read returns the DR latch only for output bits; input bits
               (GDIR=0) return the pad value - MCIMX51RM §35.4.2.1 + p1041 NOTE
               ("while GDIR=0, a read access to DR does not return DR data"). A
               board device drives a pin's pad level via SetInputPin. */
            case kOffDr: {
                const uint32_t dr_val = (dr_ & gdir_) | (input_level_ & ~gdir_);
                return dr_val;
            }
            case kOffGdir: return gdir_;
            /* PSR always returns the pad input value (MCIMX31RM §5.3.3.3). */
            case kOffPsr:
                return input_level_;
            case kOffIcr1: return icr1_;
            case kOffIcr2: return icr2_;
            case kOffImr:  return imr_;
            case kOffIsr:
                if constexpr (kIrqLow16 >= 0) {
                    std::lock_guard<std::mutex> lk(irq_mu_);
                    return isr_ | LiveLevelIsrLocked();
                }
                return isr_;
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - kBase;
        if constexpr (kSoc == SocId::Imx51) {
            if (off == kOffEdgeSel) { edge_sel_ = value; RecomputeIrq(); return; }
        }
        switch (off) {
            case kOffDr:   dr_   = value; if (write_obs_) write_obs_(); return;
            case kOffGdir:
                gdir_ = value; if (write_obs_) write_obs_(); return;
            case kOffIcr1: icr1_ = value; RecomputeIrq(); return;
            case kOffIcr2: icr2_ = value; RecomputeIrq(); return;
            case kOffImr:  imr_  = value; RecomputeIrq(); return;
            /* ISR bits are w1c (the guest's GPIO ISR + DDKGpioClearIntrPin ack the
               interrupt here). Clearing the last unmasked bit drops the TZIC line. */
            case kOffIsr:  isr_ &= ~value; RecomputeIrq(); return;
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

    /* Re-drive the OR'd TZIC line from the restored ICR/IMR/ISR + pad levels: a
       level-driving source must re-assert its INTC line after a restore. */
    void PostRestore() override {
        if constexpr (kIrqLow16 >= 0) {
            std::lock_guard<std::mutex> lk(irq_mu_);
            irq_low_asserted_  = false;
            irq_high_asserted_ = false;
            RecomputeIrqLocked();
        }
    }

    void SaveState(StateWriter& w) override {
        w.Write("dr", dr_);   w.Write("gdir", gdir_); w.Write("icr1", icr1_);
        w.Write("icr2", icr2_); w.Write("imr", imr_);  w.Write("isr", isr_);
        w.Write("input_level", input_level_);
        if constexpr (kSoc == SocId::Imx51) w.Write("edge_sel", edge_sel_);
    }
    void RestoreState(StateReader& r) override {
        r.Read("dr", dr_);   r.Read("gdir", gdir_); r.Read("icr1", icr1_);
        r.Read("icr2", icr2_); r.Read("imr", imr_);  r.Read("isr", isr_);
        r.Read("input_level", input_level_);
        if constexpr (kSoc == SocId::Imx51) r.Read("edge_sel", edge_sel_);
    }

private:
    void SetLevelBit(uint32_t pin, bool level) {
        if (level) input_level_ |=  (1u << pin);
        else       input_level_ &= ~(1u << pin);
    }

    /* 2-bit interrupt config for a pin (MCIMX51RM Table 35-8): 00 low-level,
       01 high-level, 10 rise-edge, 11 fall-edge; ICR1 = pins 0..15, ICR2 = 16..31. */
    uint32_t IcrCfg(uint32_t pin) const {
        return pin < 16u ? (icr1_ >> (2u * pin)) & 3u
                         : (icr2_ >> (2u * (pin - 16u))) & 3u;
    }

    /* Set the sticky ISR bit if this transition matches the pin's edge config.
       EDGE_SEL forces any-edge (MCIMX51RM §35.3 EDGE_SEL overrides ICR). Level
       configs (00/01) contribute live in LiveLevelIsrLocked, not here. */
    void DetectEdgeLocked(uint32_t pin, bool prev, bool level) {
        const bool edge_sel = ((edge_sel_ >> pin) & 1u) != 0u;
        bool fire;
        if (edge_sel) {
            fire = (prev != level);
        } else {
            switch (IcrCfg(pin)) {
                case 0b10u: fire = (!prev && level); break;
                case 0b11u: fire = (prev && !level);  break;
                default:    fire = false;             break;
            }
        }
        if (fire) isr_ |= (1u << pin);
    }

    uint32_t LiveLevelIsrLocked() const {
        uint32_t live = 0u;
        for (uint32_t pin = 0u; pin < 32u; ++pin) {
            /* Only pins a board device actually drives have a modeled level;
               an undriven pin defaults low, so without this a guest low-level
               (00) IMR on it would assert forever. */
            if (((driven_mask_ >> pin) & 1u) == 0u) continue;
            if (((edge_sel_ >> pin) & 1u) != 0u) continue;
            const bool level = ((input_level_ >> pin) & 1u) != 0u;
            switch (IcrCfg(pin)) {
                case 0b00u: if (!level) live |= (1u << pin); break;
                case 0b01u: if (level)  live |= (1u << pin); break;
                default: break;
            }
        }
        return live;
    }

    void RecomputeIrq() {
        if constexpr (kIrqLow16 >= 0) {
            std::lock_guard<std::mutex> lk(irq_mu_);
            RecomputeIrqLocked();
        }
    }

    void RecomputeIrqLocked() {
        const uint32_t eff = (isr_ | LiveLevelIsrLocked()) & imr_;
        const bool low = (eff & 0x0000FFFFu) != 0u;
        if (low != irq_low_asserted_) {
            irq_low_asserted_ = low;
            auto& intc = emu_.Get<IrqController>();
            if (low) intc.AssertIrq(kIrqLow16);
            else     intc.DeAssertIrq(kIrqLow16);
        }
        if constexpr (kIrqHigh16 >= 0) {
            const bool high = (eff & 0xFFFF0000u) != 0u;
            if (high != irq_high_asserted_) {
                irq_high_asserted_ = high;
                auto& intc = emu_.Get<IrqController>();
                if (high) intc.AssertIrq(kIrqHigh16);
                else      intc.DeAssertIrq(kIrqHigh16);
            }
        }
    }

    uint32_t dr_       = 0;
    uint32_t gdir_     = 0;
    uint32_t icr1_     = 0;
    uint32_t icr2_     = 0;
    uint32_t imr_      = 0;
    uint32_t isr_      = 0;
    uint32_t edge_sel_ = 0;   /* i.MX51 only */
    uint32_t input_level_ = 0;  /* board-driven input pin levels read back via PSR */
    uint32_t driven_mask_ = 0;  /* pins a board device has driven (level-IRQ scope) */
    std::function<void()> write_obs_;  /* fired on DR/GDIR write (bit-bang observers) */
    std::mutex irq_mu_;
    bool irq_low_asserted_  = false;
    bool irq_high_asserted_ = false;
};

}  /* namespace cerf_freescale_gpio_detail */
