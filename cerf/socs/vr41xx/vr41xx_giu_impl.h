#pragma once

#include "vr41xx_giu.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "vr41xx_icu.h"

#include <cstdint>
#include <mutex>

namespace cerf_vr41xx_giu_detail {

/* VR4121 UM Table 1-9 == VR4102 UM Table 18-2. */
constexpr uint32_t kOffIoSelL    = 0x00u;   /* GIUIOSELL    (VR4121 19.2.1,  VR4102 18.2.1)  */
constexpr uint32_t kOffIoSelH    = 0x02u;   /* GIUIOSELH    (VR4121 19.2.2,  VR4102 18.2.2)  */
constexpr uint32_t kOffPiodL     = 0x04u;   /* GIUPIODL     (VR4121 19.2.3,  VR4102 18.2.3)  */
constexpr uint32_t kOffPiodH     = 0x06u;   /* GIUPIODH     (VR4121 19.2.4,  VR4102 18.2.4)  */
constexpr uint32_t kOffIntStatL  = 0x08u;   /* GIUINTSTATL  (VR4121 19.2.5,  VR4102 18.2.5)  */
constexpr uint32_t kOffIntStatH  = 0x0Au;   /* GIUINTSTATH  (VR4121 19.2.6,  VR4102 18.2.6)  */
constexpr uint32_t kOffIntEnL    = 0x0Cu;   /* GIUINTENL    (VR4121 19.2.7,  VR4102 18.2.7)  */
constexpr uint32_t kOffIntEnH    = 0x0Eu;   /* GIUINTENH    (VR4121 19.2.8,  VR4102 18.2.8)  */
constexpr uint32_t kOffIntTypL   = 0x10u;   /* GIUINTTYPL   (VR4121 19.2.9,  VR4102 18.2.9)  */
constexpr uint32_t kOffIntTypH   = 0x12u;   /* GIUINTTYPH   (VR4121 19.2.10, VR4102 18.2.10) */
constexpr uint32_t kOffIntAlSelL = 0x14u;   /* GIUINTALSELL (VR4121 19.2.11, VR4102 18.2.11) */
constexpr uint32_t kOffIntAlSelH = 0x16u;   /* GIUINTALSELH (VR4121 19.2.12, VR4102 18.2.12) */
constexpr uint32_t kOffIntHtSelL = 0x18u;   /* GIUINTHTSELL (VR4121 19.2.13, VR4102 18.2.13) */
constexpr uint32_t kOffIntHtSelH = 0x1Au;   /* GIUINTHTSELH (VR4121 19.2.14, VR4102 18.2.14) */
constexpr uint32_t kOffPoDatL    = 0x1Cu;   /* GIUPODATL    (VR4121 19.2.15, VR4102 18.2.15) */
constexpr uint32_t kOffPoDatH    = 0x1Eu;   /* GIUPODATH    (VR4121 19.2.16, VR4102 18.2.16) */

/* GIUIOSELL IOS15: "Since GPIO15 (DCD#) is fixed as input, IOS15 cannot be set for
   output" - R, where IOS(14:0) are R/W (VR4121 UM 19.2.1, VR4102 UM 18.2.1). */
constexpr uint16_t kIoSelLWritable = 0x7FFFu;

/* GIUPODATH D9:8 PIOEN(1:0) and D1:0 PIOD(49:48) are R/W; D15:10 and D7:2 carry an "R"
   column on all three (VR4111 UM 19.2.16 p416, VR4121 UM 19.2.16 p464, VR4102 UM 18.2.16
   p380), which the VR4111 and VR4121 tables gloss "Write 0 to these bits. 0 is returned
   after a read" and the VR4102 table names only "Reserved". */
constexpr uint16_t kPoDatHWritable = 0x0303u;

struct Vr41xxGiuModel {
    uint32_t base;
    uint32_t size;
    uint16_t podat_l_power_on;           /* GIUPODATL RTCRST column */
    bool     intstat_sets_while_disabled;
    bool     inten_gates_icu_input;
    bool     podat_l_retained_on_reset;  /* GIUPODATL After-reset / Other-resets column */
    bool     podat_h_retained_on_reset;  /* GIUPODATH After-reset / Other-resets column */
};

template <SocFamily Soc, Vr41xxGiuModel M>
class Vr41xxGiuBase : public Vr41xxGiu {
public:
    using Vr41xxGiu::Vr41xxGiu;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == Soc;
    }

    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind kind) {
            std::lock_guard<std::mutex> lk(mtx_);
            ApplyResetLocked(kind);
        });
    }

    uint32_t MmioBase() const override { return M.base; }
    uint32_t MmioSize() const override { return M.size; }

    bool GetPinLevel(int pin) override {
        if (pin < 0 || pin > 31) {
            emu_.Get<Fatal>().Die("Vr41xxGiu::GetPinLevel: pin %d is outside GPIO(31:0)", pin);
        }
        std::lock_guard<std::mutex> lk(mtx_);
        return ((EffectivePinsLocked() >> pin) & 1u) != 0u;
    }

    uint16_t ReadHalf(uint32_t addr) override {
        std::lock_guard<std::mutex> lk(mtx_);
        return ReadHalfLocked(addr - M.base);
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        std::lock_guard<std::mutex> lk(mtx_);
        WriteHalfLocked(addr - M.base, value);
    }

    /* The GIU sits in Internal I/O space 2, 0x0B000000-0x0BFFFFFF (VR4121 UM Table 6-6),
       which is accessible in 4-byte and 2-byte units and NOT in 1-byte units (VR4121 UM
       Table 11-7, VR4102 UM Table 10-4). */
    uint32_t ReadWord(uint32_t addr) override {
        std::lock_guard<std::mutex> lk(mtx_);
        const uint32_t off = addr - M.base;
        return static_cast<uint32_t>(ReadHalfLocked(off)) |
               (static_cast<uint32_t>(ReadHalfLocked(off + 2)) << 16);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        std::lock_guard<std::mutex> lk(mtx_);
        const uint32_t off = addr - M.base;
        WriteHalfLocked(off,     static_cast<uint16_t>(value & 0xFFFFu));
        WriteHalfLocked(off + 2, static_cast<uint16_t>(value >> 16));
    }

    void SetPinLevel(int pin, bool level) override {
        if (pin < 0 || pin > 31) {
            emu_.Get<Fatal>().Die("Vr41xxGiu::SetPinLevel: pin %d is outside GPIO(31:0)", pin);
        }
        std::lock_guard<std::mutex> lk(mtx_);

        const bool     high = pin >= 16;
        const uint16_t bit  = static_cast<uint16_t>(1u << (pin & 15));
        uint16_t&      stat = high ? intstat_h_  : intstat_l_;
        const uint16_t typ   = high ? inttyp_h_   : inttyp_l_;
        const uint16_t alsel = high ? intalsel_h_ : intalsel_l_;
        const uint16_t htsel = high ? inthtsel_h_ : inthtsel_l_;
        const uint16_t en    = high ? inten_h_    : inten_l_;

        const uint32_t pinbit = 1u << pin;
        const bool     prev   = (level_ & pinbit) != 0;
        if (level) level_ |= pinbit;
        else       level_ &= ~pinbit;

        /* GIUINTTYP "1: Edge" - "an interrupt is triggered when the signal state changes
           from low to high or from high to low"; "0: Level" - "the level set to the
           corresponding bit in the GIUINTALSEL register is detected", "1: High active /
           0: Low active" (VR4121 UM 19.2.9-19.2.12, VR4102 UM 18.2.9-18.2.12). */
        const bool edge      = (typ & bit) != 0;
        const bool triggered = edge ? (prev != level) : (level == ((alsel & bit) != 0));
        const bool hold      = (htsel & bit) != 0;

        if (triggered) {
            /* INTS is set "when the signal input to the GPIO pin meets the condition set
               via the GIUINTTYPL ... or the GIUINTALSELL register" (VR4121 UM 19.2.5,
               19.2.6), but only "when '1' is set to the corresponding INTE bit in the
               GIUINTENL register and ..." (VR4102 UM 18.2.5, 18.2.6). */
            if constexpr (M.intstat_sets_while_disabled) {
                stat |= bit;
            } else if (en & bit) {
                stat |= bit;
            } else if (hold) {
                /* "If '1' (hold) is set to the INTH bit while the interrupt enable bit is
                   set to 0 (prohibit interrupts), any change in the pin state is retained
                   as change data. Therefore, an interrupt still occurs when the interrupt
                   enable bit is again set to enable interrupts" (VR4102 UM 18.2.13/18.2.14). */
                (high ? retained_h_ : retained_l_) |= bit;
            }
        } else if (!edge && !hold) {
            /* GIUINTHTSEL "0: Through" - "any interrupt signal input to the corresponding
               GPIO pin is not held and is instead allowed to pass through" (VR4121 UM
               19.2.13/19.2.14, VR4102 UM 18.2.13/18.2.14). */
            stat = static_cast<uint16_t>(stat & ~bit);
        }
        DriveIcuLocked();
    }

    void SaveState(StateWriter& w) override {
        std::lock_guard<std::mutex> lk(mtx_);
        w.Write(iosel_l_);    w.Write(iosel_h_);
        w.Write(piod_out_l_); w.Write(piod_out_h_);
        w.Write(podat_l_);
        w.Write(podat_h_);
        w.Write(intstat_l_);  w.Write(intstat_h_);
        w.Write(inten_l_);    w.Write(inten_h_);
        w.Write(inttyp_l_);   w.Write(inttyp_h_);
        w.Write(intalsel_l_); w.Write(intalsel_h_);
        w.Write(inthtsel_l_); w.Write(inthtsel_h_);
        if constexpr (!M.intstat_sets_while_disabled) {
            w.Write(retained_l_);
            w.Write(retained_h_);
        }
        w.Write(level_);
    }

    void RestoreState(StateReader& r) override {
        std::lock_guard<std::mutex> lk(mtx_);
        r.Read(iosel_l_);    r.Read(iosel_h_);
        r.Read(piod_out_l_); r.Read(piod_out_h_);
        r.Read(podat_l_);
        r.Read(podat_h_);
        r.Read(intstat_l_);  r.Read(intstat_h_);
        r.Read(inten_l_);    r.Read(inten_h_);
        r.Read(inttyp_l_);   r.Read(inttyp_h_);
        r.Read(intalsel_l_); r.Read(intalsel_h_);
        r.Read(inthtsel_l_); r.Read(inthtsel_h_);
        if constexpr (!M.intstat_sets_while_disabled) {
            r.Read(retained_l_);
            r.Read(retained_h_);
        }
        r.Read(level_);
    }

    void PostRestore() override {
        std::lock_guard<std::mutex> lk(mtx_);
        DriveIcuLocked();
    }

private:
    /* IOS = 0 reads the pin (VR4111 UM 19.2.3 p401 / 19.2.4 p402, VR4102 UM 18.2.4 p366,
       VR4121 UM 19.2.4 p450); IOS = 1 reads the driven data (casio_cassiopeia_e55 nk.exe
       @0x9E816BB8 lhu / ori 0x200 / sh on 0xAB000106). */
    uint32_t EffectivePinsLocked() const {
        const uint32_t out = (static_cast<uint32_t>(piod_out_h_) << 16) | piod_out_l_;
        const uint32_t sel = (static_cast<uint32_t>(iosel_h_) << 16) | iosel_l_;
        return (out & sel) | (level_ & ~sel);
    }

    uint16_t ReadHalfLocked(uint32_t off) {
        switch (off) {
            case kOffIoSelL: return iosel_l_;
            case kOffIoSelH: return iosel_h_;
            case kOffPiodL:     return static_cast<uint16_t>(EffectivePinsLocked());
            case kOffPiodH:     return static_cast<uint16_t>(EffectivePinsLocked() >> 16);
            case kOffIntStatL:  return intstat_l_;
            case kOffIntStatH:  return intstat_h_;
            case kOffIntEnL:    return inten_l_;
            case kOffIntEnH:    return inten_h_;
            case kOffIntTypL:   return inttyp_l_;
            case kOffIntTypH:   return inttyp_h_;
            case kOffIntAlSelL: return intalsel_l_;
            case kOffIntAlSelH: return intalsel_h_;
            case kOffIntHtSelL: return inthtsel_l_;
            case kOffIntHtSelH: return inthtsel_h_;
            case kOffPoDatL:    return podat_l_;
            case kOffPoDatH:    return podat_h_;
            default: HaltUnsupportedAccess("VR41xx GIU ReadHalf", M.base + off, 0);
        }
    }

    void WriteHalfLocked(uint32_t off, uint16_t value) {
        switch (off) {
            case kOffIoSelL: iosel_l_ = static_cast<uint16_t>(value & kIoSelLWritable); return;
            /* GIUIOSELH IOS(31:16) are all R/W (VR4121 UM 19.2.2, VR4102 UM 18.2.2). */
            case kOffIoSelH: iosel_h_ = value; return;

            /* "When the value of the corresponding IOS bit in the GIUIOSEL register is
               '0', writing a value to the PIOD bit does not affect the GPIO pin (the write
               data is ignored)" (VR4121 UM 19.2.3/19.2.4, VR4102 UM 18.2.3/18.2.4). */
            case kOffPiodL:
                piod_out_l_ = static_cast<uint16_t>((piod_out_l_ & ~iosel_l_) |
                                                    (value & iosel_l_));
                return;
            case kOffPiodH:
                piod_out_h_ = static_cast<uint16_t>((piod_out_h_ & ~iosel_h_) |
                                                    (value & iosel_h_));
                return;

            case kOffPoDatL: podat_l_ = value; return;
            case kOffPoDatH: podat_h_ = static_cast<uint16_t>(value & kPoDatHWritable); return;

            /* GIUINTSTAT INTS: "Cleared to 0 when 1 is written" (VR4121 UM 19.2.5/19.2.6,
               VR4102 UM 18.2.5/18.2.6), and "any held interrupt signal is cleared when '1'
               is set to the corresponding bit in the GIUINTSTAT register" (VR4121 UM
               19.2.13/19.2.14, VR4102 UM 18.2.13/18.2.14). */
            case kOffIntStatL:
                intstat_l_  = static_cast<uint16_t>(intstat_l_ & ~value);
                retained_l_ = static_cast<uint16_t>(retained_l_ & ~value);
                DriveIcuLocked();
                return;
            case kOffIntStatH:
                intstat_h_  = static_cast<uint16_t>(intstat_h_ & ~value);
                retained_h_ = static_cast<uint16_t>(retained_h_ & ~value);
                DriveIcuLocked();
                return;

            /* "An interrupt still occurs when the interrupt enable bit is again set to
               enable interrupts" (VR4102 UM 18.2.13/18.2.14). */
            case kOffIntEnL: {
                const uint16_t promote = static_cast<uint16_t>(retained_l_ & value);
                intstat_l_  |= promote;
                retained_l_  = static_cast<uint16_t>(retained_l_ & ~promote);
                inten_l_     = value;
                DriveIcuLocked();
                return;
            }
            case kOffIntEnH: {
                const uint16_t promote = static_cast<uint16_t>(retained_h_ & value);
                intstat_h_  |= promote;
                retained_h_  = static_cast<uint16_t>(retained_h_ & ~promote);
                inten_h_     = value;
                DriveIcuLocked();
                return;
            }

            case kOffIntTypL:   inttyp_l_   = value; return;
            case kOffIntTypH:   inttyp_h_   = value; return;
            case kOffIntAlSelL: intalsel_l_ = value; return;
            case kOffIntAlSelH: intalsel_h_ = value; return;
            case kOffIntHtSelL: inthtsel_l_ = value; return;
            case kOffIntHtSelH: inthtsel_h_ = value; return;

            default: HaltUnsupportedAccess("VR41xx GIU WriteHalf", M.base + off, value);
        }
    }

    /* Every GIU register's After-reset row is 0 except GIUPODATL's and GIUPODATH's: on the
       VR4121 both read "Previous value is retained" (UM 19.2.1-19.2.16), while on the
       VR4102 GIUPODATL is all-1 and GIUPODATH is 0 (UM 18.2.1-18.2.16). GIUPIOD's input
       bits track the pin, which no reset drives. */
    void ApplyResetLocked(ResetLineKind kind) {
        iosel_l_    = 0; iosel_h_    = 0;
        piod_out_l_ = 0; piod_out_h_ = 0;
        intstat_l_  = 0; intstat_h_  = 0;
        inten_l_    = 0; inten_h_    = 0;
        inttyp_l_   = 0; inttyp_h_   = 0;
        intalsel_l_ = 0; intalsel_h_ = 0;
        inthtsel_l_ = 0; inthtsel_h_ = 0;
        if constexpr (!M.intstat_sets_while_disabled) {
            retained_l_ = 0;
            retained_h_ = 0;
        }
        if (kind == ResetLineKind::Rtc || !M.podat_l_retained_on_reset) {
            podat_l_ = M.podat_l_power_on;
        }
        if (kind == ResetLineKind::Rtc || !M.podat_h_retained_on_reset) {
            podat_h_ = 0;
        }
        DriveIcuLocked();
    }

    /* The ICU's GIUINTLREG/GIUINTHREG are read-only INTS(15:0), "Interrupt to GPIO pin.
       1: Occurred / 0: Normal" (VR4121 UM 15.2.5, VR4102 UM 14.2.5). */
    void DriveIcuLocked() {
        auto& icu = emu_.Get<Vr41xxIcu>();
        if constexpr (M.inten_gates_icu_input) {
            icu.SetGiuLow(static_cast<uint16_t>(intstat_l_ & inten_l_));
            icu.SetGiuHigh(static_cast<uint16_t>(intstat_h_ & inten_h_));
        } else {
            icu.SetGiuLow(intstat_l_);
            icu.SetGiuHigh(intstat_h_);
        }
    }

    mutable std::mutex mtx_;

    /* Every GIU register's RTCRST column is 0 except GIUPODATL's (VR4121 UM
       19.2.1-19.2.16, VR4102 UM 18.2.1-18.2.16). */
    uint16_t iosel_l_    = 0, iosel_h_    = 0;
    uint16_t piod_out_l_ = 0, piod_out_h_ = 0;
    uint16_t podat_l_    = M.podat_l_power_on;
    uint16_t podat_h_    = 0;
    uint16_t intstat_l_  = 0, intstat_h_  = 0;
    uint16_t inten_l_    = 0, inten_h_    = 0;
    uint16_t inttyp_l_   = 0, inttyp_h_   = 0;
    uint16_t intalsel_l_ = 0, intalsel_h_ = 0;
    uint16_t inthtsel_l_ = 0, inthtsel_h_ = 0;
    uint16_t retained_l_ = 0, retained_h_ = 0;
    uint32_t level_      = 0;
};

}  /* namespace cerf_vr41xx_giu_detail */
