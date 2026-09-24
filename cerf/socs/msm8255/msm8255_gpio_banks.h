#pragma once

#include "../../state/state_stream.h"

#include <atomic>
#include <cstdint>

/* Linux arch/arm/mach-msm gpiomux-v1.h: GPIOMUX_NGPIOS is 182 under
   CONFIG_ARCH_MSM7X30. */
inline constexpr uint32_t kMsm8255GpioPinCount = 182u;

/* Linux arch/arm/mach-msm gpio_hw.h under CONFIG_ARCH_MSM7X30: a bank has one
   register in each family, and every MSM_GPIO_OUT_n carries the contiguous gpio
   range that bank serves as its annotation. */
struct Msm8255GpioBank {
    uint32_t out;
    uint32_t oe;
    uint32_t int_edge;
    uint32_t int_pos;
    uint32_t int_en;
    uint32_t int_clear;
    uint32_t int_status;
    uint32_t lo;
    uint32_t hi;

    constexpr uint32_t Span() const { return hi - lo + 1u; }

    constexpr uint32_t Pins() const {
        return (uint32_t)((((uint64_t)1u) << Span()) - 1u);
    }

    constexpr bool Owns(uint32_t pin) const { return pin >= lo && pin <= hi; }
};

enum class Msm8255GpioAccess { NotMine, PinsAbsent, Served };

inline constexpr uint32_t kMsm8255GpioFamilies = 5u;

template <uint32_t kBankCount>
class Msm8255GpioBanks {
public:
    explicit Msm8255GpioBanks(const Msm8255GpioBank (&banks)[kBankCount])
        : banks_(banks) {}

    bool OwnsPin(uint32_t pin) const {
        for (uint32_t i = 0; i < kBankCount; ++i) {
            if (banks_[i].Owns(pin)) return true;
        }
        return false;
    }

    bool Read(uint32_t off, uint32_t& value) const {
        for (uint32_t i = 0; i < kBankCount; ++i) {
            if (off == banks_[i].int_status) {
                value = status_[i].load(std::memory_order_acquire);
                return true;
            }
        }
        uint32_t bank = 0;
        uint32_t fam  = 0;
        if (!Locate(off, bank, fam)) return false;
        value = regs_[bank][fam].load(std::memory_order_acquire);
        return true;
    }

    /* Linux arch/arm/mach-msm gpio_hw.h: int_edge "1=edge 0=level",
       int_pos "1=positive 0=negative"; msm7x30_gpio.c msm_gpio_irq_mask notes
       that level triggered interrupts are also latched. */
    bool SetPinLevel(uint32_t pin, bool high) {
        for (uint32_t i = 0; i < kBankCount; ++i) {
            if (!banks_[i].Owns(pin)) continue;
            const uint32_t mask = 1u << (pin - banks_[i].lo);

            const uint32_t before = in_[i].load(std::memory_order_acquire);
            const uint32_t after  = high ? (before | mask) : (before & ~mask);
            in_[i].store(after, std::memory_order_release);
            driven_[i].fetch_or(mask, std::memory_order_acq_rel);

            const bool edge = (regs_[i][2].load(std::memory_order_acquire) &
                               mask) != 0u;
            const bool pos  = (regs_[i][3].load(std::memory_order_acquire) &
                               mask) != 0u;

            const bool latch = edge ? (high != ((before & mask) != 0u) &&
                                       high == pos)
                                    : (high == pos);
            if (latch) status_[i].fetch_or(mask, std::memory_order_acq_rel);
            return true;
        }
        return false;
    }

    /* Linux arch/arm/mach-msm msm7x30_gpio.c msm_gpio_irq_mask: "level
       triggered interrupts are also latched", so a level still matching
       int_pos re-asserts as soon as int_clear drops it. */
    void RelatchLevelPins(uint32_t bank) {
        const uint32_t edge = regs_[bank][2].load(std::memory_order_acquire);
        const uint32_t pos  = regs_[bank][3].load(std::memory_order_acquire);
        const uint32_t lvl  = in_[bank].load(std::memory_order_acquire);
        const uint32_t hit  = ~edge & driven_[bank].load(std::memory_order_acquire) &
                              ~(lvl ^ pos);
        if (hit != 0u) status_[bank].fetch_or(hit, std::memory_order_acq_rel);
    }

    /* Linux arch/arm/mach-msm msm7x30_gpio.c msm_gpio_irq_handler ORs
       int_status & int_enable over every bank to find the group line. */
    bool AnyPending() const {
        for (uint32_t i = 0; i < kBankCount; ++i) {
            if ((status_[i].load(std::memory_order_acquire) &
                 regs_[i][4].load(std::memory_order_acquire)) != 0u) {
                return true;
            }
        }
        return false;
    }

    Msm8255GpioAccess Write(uint32_t off, uint32_t value, uint32_t& bank_pins) {
        uint32_t bank = 0;
        uint32_t fam  = 0;
        if (Locate(off, bank, fam)) {
            bank_pins = banks_[bank].Pins();
            if ((value & ~bank_pins) != 0u) {
                return Msm8255GpioAccess::PinsAbsent;
            }
            regs_[bank][fam].store(value, std::memory_order_release);
            return Msm8255GpioAccess::Served;
        }
        for (uint32_t i = 0; i < kBankCount; ++i) {
            if (off != banks_[i].int_clear) continue;
            bank_pins = banks_[i].Pins();
            if ((value & ~bank_pins) != 0u) {
                return Msm8255GpioAccess::PinsAbsent;
            }
            status_[i].fetch_and(~value, std::memory_order_acq_rel);
            RelatchLevelPins(i);
            return Msm8255GpioAccess::Served;
        }
        return Msm8255GpioAccess::NotMine;
    }

    void Reset() {
        for (uint32_t i = 0; i < kBankCount; ++i) {
            in_[i].store(0u, std::memory_order_release);
            driven_[i].store(0u, std::memory_order_release);
            status_[i].store(0u, std::memory_order_release);
            for (uint32_t f = 0; f < kMsm8255GpioFamilies; ++f) {
                regs_[i][f].store(0u, std::memory_order_release);
            }
        }
    }

    void Save(StateWriter& w) const {
        for (uint32_t i = 0; i < kBankCount; ++i) {
            w.Write<uint32_t>("in", in_[i].load(std::memory_order_acquire));
            w.Write<uint32_t>("driven", driven_[i].load(std::memory_order_acquire));
            w.Write<uint32_t>("status", status_[i].load(std::memory_order_acquire));
            for (uint32_t f = 0; f < kMsm8255GpioFamilies; ++f) {
                w.Write<uint32_t>("regs", regs_[i][f].load(std::memory_order_acquire));
            }
        }
    }

    bool Restore(StateReader& r, uint32_t& bad_off, uint32_t& bad_value) {
        for (uint32_t i = 0; i < kBankCount; ++i) {
            uint32_t level = 0;
            uint32_t drv   = 0;
            uint32_t stat  = 0;
            r.Read("in", level);
            r.Read("driven", drv);
            r.Read("status", stat);
            if (((level | drv | stat) & ~banks_[i].Pins()) != 0u) {
                bad_off   = banks_[i].int_status;
                bad_value = level | drv | stat;
                return false;
            }
            in_[i].store(level, std::memory_order_release);
            driven_[i].store(drv, std::memory_order_release);
            status_[i].store(stat, std::memory_order_release);
            for (uint32_t f = 0; f < kMsm8255GpioFamilies; ++f) {
                uint32_t value = 0;
                r.Read("regs", value);
                if ((value & ~banks_[i].Pins()) != 0u) {
                    bad_off   = FamilyOffset(banks_[i], f);
                    bad_value = value;
                    return false;
                }
                regs_[i][f].store(value, std::memory_order_release);
            }
        }
        return true;
    }

private:
    static_assert(kMsm8255GpioFamilies == 5u,
                  "FamilyOffset enumerates exactly the read-write families");

    static constexpr uint32_t FamilyOffset(const Msm8255GpioBank& b,
                                           uint32_t fam) {
        switch (fam) {
        case 0u: return b.out;
        case 1u: return b.oe;
        case 2u: return b.int_edge;
        case 3u: return b.int_pos;
        default: return b.int_en;
        }
    }

    bool Locate(uint32_t off, uint32_t& bank, uint32_t& fam) const {
        for (uint32_t i = 0; i < kBankCount; ++i) {
            for (uint32_t f = 0; f < kMsm8255GpioFamilies; ++f) {
                if (off == FamilyOffset(banks_[i], f)) {
                    bank = i;
                    fam  = f;
                    return true;
                }
            }
        }
        return false;
    }

    const Msm8255GpioBank* banks_;

    std::atomic<uint32_t> regs_[kBankCount][kMsm8255GpioFamilies] = {};
    std::atomic<uint32_t> in_[kBankCount]                         = {};
    std::atomic<uint32_t> driven_[kBankCount]                     = {};
    std::atomic<uint32_t> status_[kBankCount]                     = {};
};
