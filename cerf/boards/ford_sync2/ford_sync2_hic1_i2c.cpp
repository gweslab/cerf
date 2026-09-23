#include "../../core/service.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../board_context.h"
#include "ford_sync_2_id.h"
#include "../../socs/imx51/imx51_gpio4.h"
#include "../../jit/arm/arm_cpu.h"
#include "../../jit/arm/arm_mmu_probe.h"
#include "../../peripherals/cirrus_cs42448/cs42448_codec.h"
#include "../../peripherals/ti_tsc2003/ti_tsc2003_touch.h"

#include <cstdint>
#include <cstdio>

namespace {

/* Ford SYNC2 "HIC1:" = software-I2C bit-banged over GPIO4 (SCL=16/SDA=17,
   hsi2c.dll), NOT the HS-I2C at 0x70038000; slaves camera 0x20 / DM 0x38 /
   CS42448 0x48 / TSC2003 0x49, decoded off GPIO4's write-observer. */
constexpr uint32_t kScl = 16u;
constexpr uint32_t kSda = 17u;

/* CS42448 audio codec (wavedev2_cs42448.dll CS42448CodecContext). */
constexpr uint8_t kCs42448Addr = 0x48u;

/* Display-module panel-detect slave (DisplayModule.dll DMX_Init sub_C0E326CC ->
   DMI2CXfer sub_C0E31D08: a single 6-byte read from 0x38). */
constexpr uint8_t kDmAddr = 0x38u;

/* TSC2003 touch-screen controller (touch_tsc2003.dll TSCI2CInit). */
constexpr uint8_t kTsc2003Addr = 0x49u;

class FordSync2Hic1I2c : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::FordSync2;
    }
    void OnReady() override {
        gpio_ = &emu_.Get<Imx51Gpio4>();
        tsc2003_ = &emu_.Get<Tsc2003Touch>();
        /* Both lines idle high (open-drain pull-up). SCL especially: the slave
           never clock-stretches, so the master's WaitForSCK readback (hsi2c
           releases GPIO4.16 then waits for it to read high) must read high -
           else it times out (0x102) every clock and the I2C crawls. */
        gpio_->SetInputPin(kScl, true);
        gpio_->SetInputPin(kSda, true);
        gpio_->SetWriteObserver([this] { OnEdge(); });
    }

private:
    void DriveSda(bool level) { gpio_->SetInputPin(kSda, level); }
    void ReleaseSda()         { DriveSda(true); }

    [[noreturn]] void FatalUnmodelledSlave() const {
        const ArmCpuState* st = emu_.Get<ArmCpu>().State();
        const uint32_t sp = st->gprs[ArmGpr::kR13];
        ArmMmuProbe& probe = emu_.Get<ArmMmuProbe>();
        auto rd = [&](uint32_t va) -> uint32_t {
            uint8_t* p = probe.PeekVaToHost(va);
            return p ? cerf::le::U32(p) : 0u;
        };
        char chain[320];
        int o = 0;
        chain[0] = 0;
        uint32_t logged = 0;
        for (uint32_t i = 0; i < 512u && logged < 32u; ++i) {
            const uint32_t w = rd(sp + i * 4u);
            if (w < 0xC0000000u || w >= 0xC2000000u) continue;
            if ((rd(w - 4u) >> 24) != 0xEBu) continue;
            if (o < static_cast<int>(sizeof(chain)) - 9)
                o += std::snprintf(chain + o, sizeof(chain) - o, "%08X ", w);
            ++logged;
        }
        LOG(Caution,
            "[HIC1] unmodelled I2C slave=0x%02X rw=%u pc=0x%08X lr=0x%08X "
            "sp=0x%08X chain: %s\n",
            addr_, static_cast<unsigned>(rw_), st->gprs[ArmGpr::kR15],
            st->gprs[ArmGpr::kR14], sp, chain);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    void OnByteReceived(uint8_t b) {
        if (byte_idx_ == 0u) {                /* address byte */
            addr_ = b >> 1; rw_ = b & 1u;
            addressed_ = (addr_ == kCs42448Addr || addr_ == kDmAddr ||
                          addr_ == kTsc2003Addr);
            map_set_ = false;
            if (!addressed_) FatalUnmodelledSlave();
        } else if (addr_ == kTsc2003Addr) {
            tsc2003_->WriteCommand(b);
        } else if (addr_ == kDmAddr) {
            /* DM 0x38 config write [reg][val] (reg 1 brightness / 2 mode / 3 touch;
               displaymodule sub_C0E31F70 / sub_C0E31FD4 via DMI2CXfer sub_C0E31D08): the
               panel accepts it and the only 0x38 read is the fixed 6-byte detect, so
               nothing reads these back - accept the bytes with no stored register state. */
        } else if (!map_set_) {               /* codec register pointer (MAP) */
            reg_ = b & 0x7Fu;
            auto_incr_ = (b & 0x80u) != 0u;
            map_set_ = true;
        } else {                              /* data write byte */
            cs42448_.WriteReg(reg_, b);
            if (auto_incr_) reg_ = static_cast<uint8_t>((reg_ + 1u) & 0x7Fu);
        }
    }

    /* DisplayModule.dll DMIntHandlerThread sub_C09B2178: byte1/byte3-hi ->
       Buffer[1]=UncalX, byte2/byte3-lo -> Buffer[2]=UncalY (WriteMsgQueue), fed as
       TouchPanelCalibrateAPoint(UncalX,UncalY) so byte1/byte3-hi carries AdcX. byte5
       (v&7)=DM8(2) else DMX_Init raises DisplaySystemError, (v&8)=touch. */
    uint8_t DmReadByte() const {
        const bool pen = tsc2003_->PenDown();
        const uint16_t x = tsc2003_->AdcX();
        const uint16_t y = tsc2003_->AdcY();
        switch (byte_idx_) {
            case 1u: return pen ? 0x83u : 0x00u;            /* pending|touch|pen */
            case 2u: return pen ? static_cast<uint8_t>(x >> 4) : 0x00u;
            case 3u: return pen ? static_cast<uint8_t>(y >> 4) : 0x00u;
            case 4u: return pen ? static_cast<uint8_t>(((x & 0xFu) << 4) | (y & 0xFu))
                                : 0x00u;
            case 5u: return 0x00u;                          /* error flags */
            case 6u: return 0x0Au;                          /* DM8 + touch */
            default: return 0x00u;
        }
    }

    void OnEdge() {
        /* Open-drain wired-AND: a line is high only if released (input or
           output-high) AND nothing pulls it low; the slave's ACK pull is in the
           same input_level_ the master reads back, so both lines read symmetrically. */
        const bool scl = (!gpio_->PinIsOutput(kScl) || gpio_->PinOutLevel(kScl)) &&
                         gpio_->PinInputLevel(kScl);
        const bool sda = (!gpio_->PinIsOutput(kSda) || gpio_->PinOutLevel(kSda)) &&
                         gpio_->PinInputLevel(kSda);

        if (scl && prev_scl_) {                       /* SDA edge while SCL high */
            if (prev_sda_ && !sda) {                  /* (repeated) START - reg_ kept */
                active_ = true; bit_ = 0u; shift_ = 0u;
                tx_this_ = false; byte_idx_ = 0u; addressed_ = false;
                master_nack_ = false;
                ReleaseSda();
            } else if (!prev_sda_ && sda) {           /* STOP */
                active_ = false; ReleaseSda();
            }
        } else if (active_) {
            if (prev_scl_ && !scl) {                  /* SCL falling - set up next bit */
                if (bit_ < 8u) {
                    if (tx_this_ && addressed_) DriveSda((tx_byte_ >> (7u - bit_)) & 1u);
                    else ReleaseSda();
                } else {                              /* ACK bit */
                    if (!tx_this_ && addressed_) DriveSda(false);  /* slave ACKs RX byte */
                    else ReleaseSda();                /* master ACKs our TX byte */
                }
            } else if (!prev_scl_ && scl) {           /* SCL rising - sample */
                if (bit_ < 8u) {
                    if (!tx_this_) shift_ = (shift_ << 1) | (sda ? 1u : 0u);
                    if (++bit_ == 8u && !tx_this_)    /* RX byte done BEFORE its ACK */
                        OnByteReceived(static_cast<uint8_t>(shift_));
                } else {                              /* ACK clock */
                    if (tx_this_) master_nack_ = sda;
                    bit_ = 0u; shift_ = 0u; ++byte_idx_;
                    tx_this_ = addressed_ && rw_ && !master_nack_;  /* read -> TX next byte */
                    if (tx_this_) {
                        if (addr_ == kDmAddr) {
                            tx_byte_ = DmReadByte();
                        } else if (addr_ == kTsc2003Addr) {
                            tx_byte_ = tsc2003_->ReadResultByte();
                        } else {
                            tx_byte_ = cs42448_.ReadReg(reg_);
                            if (auto_incr_) reg_ = static_cast<uint8_t>((reg_ + 1u) & 0x7Fu);
                        }
                    }
                }
            }
        }
        prev_scl_ = scl; prev_sda_ = sda;
    }

    Imx51Gpio4* gpio_ = nullptr;
    Tsc2003Touch* tsc2003_ = nullptr;
    Cs42448Codec cs42448_;
    bool prev_scl_ = true;
    bool prev_sda_ = true;
    bool active_ = false;
    bool tx_this_ = false;    /* current byte is slave-transmitted (read data) */
    bool addressed_ = false;
    bool rw_ = false;
    bool master_nack_ = false;
    bool map_set_ = false;
    bool auto_incr_ = false;
    uint32_t bit_ = 0;
    uint32_t shift_ = 0;
    uint8_t  byte_idx_ = 0;
    uint8_t  addr_ = 0;
    uint8_t  reg_ = 0;
    uint8_t  tx_byte_ = 0;
};

}  /* namespace */

REGISTER_SERVICE(FordSync2Hic1I2c);
