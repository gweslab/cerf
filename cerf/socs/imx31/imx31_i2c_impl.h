#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace cerf_imx31_i2c_detail {

/* MCIMX31RM Table 26-3/26-4 (Ch 26 I2C). 16-bit registers, 16 KB window. */
constexpr uint32_t kSize = 0x00004000u;

constexpr uint32_t kOffIadr = 0x00u;
constexpr uint32_t kOffIfdr = 0x04u;
constexpr uint32_t kOffI2cr = 0x08u;
constexpr uint32_t kOffI2sr = 0x0Cu;
constexpr uint32_t kOffI2dr = 0x10u;

constexpr uint16_t kI2crMsta = 0x20u;  /* master mode: 0->1 START, 1->0 STOP */

constexpr uint16_t kI2srIcf  = 0x80u;  /* data transfer complete */
constexpr uint16_t kI2srIbb  = 0x20u;  /* bus busy */
constexpr uint16_t kI2srIal  = 0x10u;  /* arbitration lost */
constexpr uint16_t kI2srIif  = 0x02u;  /* interrupt flag (w0c) */
constexpr uint16_t kI2srRxak = 0x01u;  /* 0 = ACK received */

template <uint32_t kBase>
class Imx31I2cImpl : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::iMX31;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint16_t ReadHalf(uint32_t addr) override {
        switch (addr - kBase) {
            case kOffIadr: return iadr_;
            case kOffIfdr: return ifdr_;
            case kOffI2cr: return i2cr_;
            case kOffI2sr: return i2sr_;
            case kOffI2dr: i2sr_ |= kI2srIcf; return i2dr_;
        }
        HaltUnsupportedAccess("ReadHalf", addr, 0);
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        switch (addr - kBase) {
            case kOffIadr: iadr_ = value; return;
            case kOffIfdr: ifdr_ = value; return;
            case kOffI2cr: {
                const bool was_master = (i2cr_ & kI2crMsta) != 0;
                const bool is_master  = (value & kI2crMsta) != 0;
                i2cr_ = value;
                if (!was_master && is_master)      i2sr_ |= kI2srIbb;
                else if (was_master && !is_master) i2sr_ &= ~(kI2srIbb | kI2srIcf);
                return;
            }
            /* IIF/IAL are write-0-to-clear (Table 26-4). */
            case kOffI2sr: i2sr_ &= (value | ~(kI2srIif | kI2srIal)); return;
            /* Audio careful stub (§0.3): accept the codec byte, complete the
               transfer instantly with ACK so the polling driver proceeds. */
            case kOffI2dr:
                i2dr_ = value;
                i2sr_ |= (kI2srIcf | kI2srIif);
                i2sr_ &= ~kI2srRxak;
                return;
        }
        HaltUnsupportedAccess("WriteHalf", addr, value);
    }

private:
    uint16_t iadr_ = 0, ifdr_ = 0, i2cr_ = 0, i2sr_ = 0, i2dr_ = 0;
};

}  /* namespace cerf_imx31_i2c_detail */
