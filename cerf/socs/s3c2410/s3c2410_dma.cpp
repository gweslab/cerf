#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../irq_controller.h"
#include "s3c2410_iis.h"

#include <cstdint>
#include <mutex>

namespace {

class S3C2410Dma : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::S3C2410;
    }

    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    /* Covers DMA1 + DMA2 inclusive: 0x4B000040..0x4B0000BF (0x80
       bytes). Channel stride is 0x40 — within each channel the BSP
       reserves the full 0x40 even though the highest used register
       (DMASKTRIG) is at +0x20. */
    uint32_t MmioBase() const override { return 0x4B000040u; }
    uint32_t MmioSize() const override { return 0x00000080u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    static constexpr uint32_t kChannelStride = 0x40u;

    static constexpr uint32_t kRegDISRC     = 0x00u;
    static constexpr uint32_t kRegDISRCC    = 0x04u;
    static constexpr uint32_t kRegDIDST     = 0x08u;
    static constexpr uint32_t kRegDIDSTC    = 0x0Cu;
    static constexpr uint32_t kRegDCON      = 0x10u;
    static constexpr uint32_t kRegDSTAT     = 0x14u;
    static constexpr uint32_t kRegDCSRC     = 0x18u;
    static constexpr uint32_t kRegDCDST     = 0x1Cu;
    static constexpr uint32_t kRegDMASKTRIG = 0x20u;

    /* Bit-field positions per BSP DMASKTRIG / DCON unions in
       dev_emu boards/smdk2410/devices.h. */
    static constexpr uint32_t kDmasktrigOnOff = 1u << 1;
    static constexpr uint32_t kDconTcMask     = 0x000FFFFFu;
    static constexpr uint32_t kDconDszShift   = 20u;
    static constexpr uint32_t kDconDszMask    = 0x3u;
    static constexpr uint32_t kDconReloadBit  = 1u << 22;

    struct Channel {
        uint32_t disrc     = 0;
        uint32_t disrcc    = 0;
        uint32_t didst     = 0;
        uint32_t didstc    = 0;
        uint32_t dcon      = 0;
        uint32_t dstat     = 0;
        uint32_t dcsrc     = 0;
        uint32_t dcdst     = 0;
        uint32_t dmasktrig = 0;
    };

    std::mutex state_mutex_;
    Channel    channels_[2] = {};   /* [0] = DMA1, [1] = DMA2 */
};

uint32_t S3C2410Dma::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    const uint32_t ch  = off / kChannelStride;
    const uint32_t reg = off & (kChannelStride - 1u);
    if (ch >= 2) HaltUnsupportedAccess("ReadWord", addr, 0);  /* noreturn */

    std::lock_guard<std::mutex> lk(state_mutex_);
    const Channel& c = channels_[ch];
    switch (reg) {
        case kRegDISRC:     return c.disrc;
        case kRegDISRCC:    return c.disrcc;
        case kRegDIDST:     return c.didst;
        case kRegDIDSTC:    return c.didstc;
        case kRegDCON:      return c.dcon;
        case kRegDSTAT:     return c.dstat;
        case kRegDCSRC:     return c.dcsrc;
        case kRegDCDST:     return c.dcdst;
        case kRegDMASKTRIG: return c.dmasktrig;
        default:
            HaltUnsupportedAccess("ReadWord", addr, 0);  /* noreturn */
    }
}

void S3C2410Dma::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    const uint32_t ch  = off / kChannelStride;
    const uint32_t reg = off & (kChannelStride - 1u);
    if (ch >= 2) HaltUnsupportedAccess("WriteWord", addr, value);  /* noreturn */

    LOG(Periph, "[Dma%u] write +0x%02X = 0x%08X\n",
            ch + 1, reg, value);

    /* Audio-output coupling actions decided under the lock and
       executed after release — IIS and IrqController have their own
       locks, never nest. */
    bool     queue_output       = false;
    bool     set_output_dma_on  = false;
    bool     set_output_dma_off = false;
    uint32_t queue_src_pa       = 0;
    uint32_t queue_bytes        = 0;

    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        Channel& c = channels_[ch];
        switch (reg) {
            case kRegDISRC:
                c.disrc = value;
                /* BSP IODMAController2::WriteWord case 0:
                     if (DMASKTRIG.ON_OFF && DCON.RELOAD == 0)
                       IIS.QueueOutput(host(DISRC.S_ADDR),
                                       DSTAT * (DCON.DSZ << 1)); */
                if (ch == 1 &&
                    (c.dmasktrig & kDmasktrigOnOff) &&
                    !(c.dcon     & kDconReloadBit)) {
                    const uint32_t dsz =
                        (c.dcon >> kDconDszShift) & kDconDszMask;
                    queue_src_pa = c.disrc;
                    queue_bytes  = c.dstat * (dsz << 1);
                    queue_output = true;
                }
                break;
            case kRegDISRCC:    c.disrcc = value; break;
            case kRegDIDST:     c.didst  = value; break;
            case kRegDIDSTC:    c.didstc = value; break;
            case kRegDCON:      c.dcon   = value; break;
            case kRegDSTAT:     /* read-only in BSP */ break;
            case kRegDCSRC:     /* read-only */        break;
            case kRegDCDST:     /* read-only */        break;
            case kRegDMASKTRIG:
                c.dmasktrig = value;
                if (ch == 1) {
                    /* BSP IODMAController2::WriteWord case 0x20. */
                    if (value & kDmasktrigOnOff) {
                        const uint32_t tc =
                            c.dcon & kDconTcMask;
                        const uint32_t dsz =
                            (c.dcon >> kDconDszShift) & kDconDszMask;
                        c.dstat            = tc;  /* DSTAT = DCON.TC */
                        queue_src_pa       = c.disrc;
                        queue_bytes        = tc * (dsz << 1);
                        queue_output       = true;
                        set_output_dma_on  = true;
                    } else {
                        set_output_dma_off = true;
                    }
                }
                break;
            default:
                HaltUnsupportedAccess("WriteWord", addr, value);  /* noreturn */
        }
    }

    if (set_output_dma_on || set_output_dma_off || queue_output) {
        auto& iis = emu_.Get<S3C2410Iis>();
        if (set_output_dma_on)  iis.SetOutputDMA(true);
        if (set_output_dma_off) iis.SetOutputDMA(false);
        if (queue_output) {
            const uint8_t* src =
                emu_.Get<EmulatedMemory>().TryTranslate(queue_src_pa);
            if (!src) {
                LOG(Caution, "[Dma2] queue_src_pa 0x%08X unmapped\n",
                        queue_src_pa);
                return;
            }
            iis.QueueOutput(src, queue_bytes);
        }
    }
}

}  /* namespace */

REGISTER_SERVICE(S3C2410Dma);
