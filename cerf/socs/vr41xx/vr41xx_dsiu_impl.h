#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../../tracing/kernel_debug_sink.h"
#include "../guest_cpu_reset.h"
#include "vr41xx_icu.h"

#include <cstdint>
#include <mutex>
#include <string>

namespace cerf_vr41xx_dsiu_detail {

/* VR4121 UM Table 23-1 == VR4102 UM Table 22-1. */
constexpr uint32_t kOffPort   = 0x00u;   /* PORTREG      (VR4121 23.2.1,  VR4102 22.2.1)  */
constexpr uint32_t kOffAsim00 = 0x04u;   /* ASIM00REG    (VR4121 23.2.3,  VR4102 22.2.3)  */
constexpr uint32_t kOffAsim01 = 0x06u;   /* ASIM01REG    (VR4121 23.2.4,  VR4102 22.2.4)  */
constexpr uint32_t kOffTxs0L  = 0x0Eu;   /* TXS0LREG     (VR4121 23.2.8,  VR4102 22.2.8)  */
constexpr uint32_t kOffAsis0  = 0x10u;   /* ASIS0REG     (VR4121 23.2.9,  VR4102 22.2.9)  */
constexpr uint32_t kOffIntr0  = 0x12u;   /* INTR0REG     (VR4121 23.2.10, VR4102 22.2.10) */
constexpr uint32_t kOffBprm0  = 0x16u;   /* BPRM0REG     (VR4121 23.2.11, VR4102 22.2.11) */
constexpr uint32_t kOffReset  = 0x18u;   /* DSIURESETREG (VR4121 23.2.12, VR4102 22.2.12) */

/* PORTREG D3 CDDIN, D2 CDDOUT, D1 CDRTS, D0 CDCTS switch each DSIU pin to a
   general-purpose output; D15:4 RFU, "Write 0 to these bits. 0 is returned after a read"
   (VR4121 UM 23.2.1, VR4102 UM 22.2.1). */
constexpr uint16_t kPortWritable = 0x000Fu;

/* ASIM00REG D6 RXE0 reception enable, D5:4 PS0(1:0) parity, D3 CL0 character length,
   D2 SL0 stop bits are R/W; D7 is an RFU that reads back 1 ("Write 1 to this bit. 1 is
   returned after a read"); D15:8 and D1:0 RFU read 0. Both reset rows carry D7
   (VR4121 UM 23.2.3, VR4102 UM 22.2.3). */
constexpr uint16_t kAsim00Writable  = 0x007Cu;
constexpr uint16_t kAsim00FixedRead = 0x0080u;

/* ASIM01REG D0 EBS0 "Extended bit operation enable"; D15:1 RFU read 0; both reset rows 0
   (VR4121 UM 23.2.4, VR4102 UM 22.2.4). */
constexpr uint16_t kAsim01Writable = 0x0001u;

/* TXS0LREG D7:0 "Transmit data"; D15:8 RFU read 0; both reset rows all 1
   (VR4121 UM 23.2.8, VR4102 UM 22.2.8). */
constexpr uint16_t kTxs0LData    = 0x00FFu;
constexpr uint16_t kTxs0LPowerOn = 0x00FFu;

/* INTR0REG D3 INTDCD, D2 INTSER0, D1 INTSR0, D0 INTST0, each "Cleared to 0 when 1 is
   written"; D15:4 RFU read 0; both reset rows 0 (VR4121 UM 23.2.10, VR4102 UM 22.2.10). */
constexpr uint16_t kIntSt0    = 0x0001u;   /* "Debug serial transmit complete interrupt" */
constexpr uint16_t kIntCauses = 0x000Fu;

/* The ICU's DSIUINTREG (0x0B00008A) carries the same four causes in D11:8 - D11 INTDCTS,
   D10 INTSER0, D9 INTSR0, D8 INTST0 - and MDSIUINTREG (0x0B000096) enables them in D11:8
   (VR4111 UM 15.2.6 p335 + 15.2.12 p342, VR4121 UM 15.2.6 + 15.2.12, VR4102 UM 14.2.6), so
   INTR0REG's D3:0 shift by 8 into the ICU's positions. */
constexpr int kIcuCauseShift = 8;

/* BPRM0REG D7 BRCE0 baud-rate-generator count enable and D2:0 BPR0(2:0) baud rate are R/W;
   D15:8 and D6:3 are "Write 0 when writing. 0 is returned after a read"; both reset rows 0
   (VR4121 UM 23.2.11, VR4102 UM 22.2.11). */
constexpr uint16_t kBprmWritable = 0x0087u;

/* DSIURESETREG D0 DSIURST "DSIU reset. Cleared to 0 when 1 is written. 1: Reset /
   0: Normal"; D15:1 RFU read 0 (VR4121 UM 23.2.12, VR4102 UM 22.2.12). */
constexpr uint16_t kDsiuRst = 0x0001u;

struct Vr41xxDsiuModel {
    uint32_t base;
    uint32_t size;
    bool     portreg_retained_on_reset;   /* PORTREG After-reset row */
};

template <const std::string_view& Soc, Vr41xxDsiuModel M>
class Vr41xxDsiuBase : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == Soc;
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

    uint16_t ReadHalf(uint32_t addr) override {
        std::lock_guard<std::mutex> lk(mtx_);
        switch (addr - M.base) {
            case kOffPort:   return portreg_;
            case kOffAsim00: return static_cast<uint16_t>(asim00_ | kAsim00FixedRead);
            case kOffAsim01: return asim01_;
            case kOffTxs0L:  return txs0l_;
            /* ASIS0REG D7 SOT0 "1: Transmission start / 0: Transmission complete", cleared
               "when the transmission is completed"; D2 PE0, D1 FE0, D0 OVE0 are receive
               error flags (VR4121 UM 23.2.9, VR4102 UM 22.2.9). */
            case kOffAsis0:  return 0u;
            case kOffIntr0:  return intr0_;
            case kOffBprm0:  return bprm0_;
            /* DSIURST is "Cleared to 0 when 1 is written" (VR4121 UM 23.2.12). */
            case kOffReset:  return 0u;
            default: return Peripheral::ReadHalf(addr);
        }
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        bool    transmitted = false;
        uint8_t tx_byte     = 0;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            switch (addr - M.base) {
                case kOffPort:   portreg_ = static_cast<uint16_t>(value & kPortWritable);  break;
                case kOffAsim00: asim00_  = static_cast<uint16_t>(value & kAsim00Writable); break;
                case kOffAsim01: asim01_  = static_cast<uint16_t>(value & kAsim01Writable); break;
                case kOffBprm0:  bprm0_   = static_cast<uint16_t>(value & kBprmWritable);   break;
                case kOffTxs0L:
                    tx_byte     = static_cast<uint8_t>(value & kTxs0LData);
                    transmitted = true;
                    TransmitLocked(tx_byte);
                    break;
                case kOffIntr0:
                    intr0_ = static_cast<uint16_t>(intr0_ & ~(value & kIntCauses));
                    DriveIcuLocked();
                    break;
                case kOffReset:
                    /* D15:1 are RFU, "Write 0 to these bits" (VR4121 UM 23.2.12). */
                    if (value & ~kDsiuRst) {
                        HaltUnsupportedAccess("VR41xx DSIU DSIURESETREG reserved bits",
                                              addr, value);
                    }
                    if (value & kDsiuRst) ApplyDsiuResetLocked();
                    break;
                default: Peripheral::WriteHalf(addr, value); break;
            }
        }
        if (transmitted) {
            emu_.Get<KernelDebugSink>().EmitChar(static_cast<char>(tx_byte), tx_line_, "DSIU");
        }
    }

    void SaveState(StateWriter& w) override {
        std::lock_guard<std::mutex> lk(mtx_);
        w.Write("portreg", portreg_); w.Write("asim00", asim00_); w.Write("asim01", asim01_);
        w.Write("txs0l", txs0l_);   w.Write("intr0", intr0_);  w.Write("bprm0", bprm0_);
    }

    void RestoreState(StateReader& r) override {
        std::lock_guard<std::mutex> lk(mtx_);
        r.Read("portreg", portreg_); r.Read("asim00", asim00_); r.Read("asim01", asim01_);
        r.Read("txs0l", txs0l_);   r.Read("intr0", intr0_);  r.Read("bprm0", bprm0_);
    }

    void PostRestore() override {
        std::lock_guard<std::mutex> lk(mtx_);
        DriveIcuLocked();
    }

private:
    /* "Writing data to a transmission shift register (TXS0REG or TXS0LREG) activates the
       transmit operation" and "Once one frame of data has been sent, a transmit complete
       interrupt request (Dsiu_Intst0) occurs" (VR4121 UM 23.3.2, VR4102 UM 22.3.2). */
    void TransmitLocked(uint8_t data) {
        txs0l_ = data;
        intr0_ |= kIntSt0;
        DriveIcuLocked();
    }

    /* "This register is used to reset the debug serial mode" (VR4102 UM 22.2.12).
       "If a reset is input, the transmit complete interrupt request (Dsiu_Intst0) will not
       occur even when the transmission shift register is empty" (VR4121 UM 23.3.2 Caution 1,
       VR4102 UM 22.3.2 Caution 1). */
    void ApplyDsiuResetLocked() {
        asim00_ = 0;
        asim01_ = 0;
        txs0l_  = kTxs0LPowerOn;
        intr0_  = 0;
        bprm0_  = 0;
        DriveIcuLocked();
    }

    /* Every DSIU register's RTCRST column equals its other-resets column except PORTREG's,
       whose After-reset row is "Previous value is retained" on the VR4121 (UM 23.2.1) and 0
       on the VR4102 (UM 22.2.1). */
    void ApplyResetLocked(ResetLineKind kind) {
        ApplyDsiuResetLocked();
        if (kind == ResetLineKind::Rtc || !M.portreg_retained_on_reset) portreg_ = 0;
    }

    /* The ICU's DSIUINTREG carries the DSIU's interrupt causes and raises SYSINT2REG
       DSIUINTR when unmasked (VR4121 UM 15.1, VR4102 UM 14.1). */
    void DriveIcuLocked() {
        const uint16_t causes = static_cast<uint16_t>(intr0_ & kIntCauses);
        emu_.Get<Vr41xxIcu>().SetDsiuSource(
            static_cast<uint16_t>(causes << kIcuCauseShift));
    }

    std::mutex mtx_;

    uint16_t portreg_ = 0;                 /* PORTREG   RTCRST row */
    uint16_t asim00_  = 0;                 /* ASIM00REG reset row, less the D7 fixed read */
    uint16_t asim01_  = 0;                 /* ASIM01REG reset row */
    uint16_t txs0l_   = kTxs0LPowerOn;     /* TXS0LREG  reset row */
    uint16_t intr0_   = 0;                 /* INTR0REG  reset row */
    uint16_t bprm0_   = 0;                 /* BPRM0REG  reset row */

    std::string tx_line_;
};

}  /* namespace cerf_vr41xx_dsiu_detail */
