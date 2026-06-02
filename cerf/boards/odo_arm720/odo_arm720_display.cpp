#define NOMINMAX

#include "../../peripherals/peripheral_base.h"
#include "../../host/frame_renderer.h"
#include "../../host/host_window.h"
#include "../../lcd/lcd_content_latch.h"

#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../cpu/emulated_memory.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>
#include <mutex>

namespace {

/* P2.H lines 212-226 (ARM branch). */
constexpr uint32_t kDisplayRegsPa  = 0x10001000u;
constexpr uint32_t kDisplayRegsSize = 0x10u;  /* CSR + XSIZE + YSIZE */

constexpr uint32_t kSlotDispCsr    = 0x04u;
constexpr uint32_t kSlotDispXSize  = 0x08u;
constexpr uint32_t kSlotDispYSize  = 0x0Cu;

constexpr uint32_t kDispDmaPa      = 0x10030810u;
constexpr uint32_t kDispDmaSize    = 0x08u;
constexpr uint32_t kSlotDmaLow     = 0x00u;
constexpr uint32_t kSlotDmaHigh    = 0x04u;

constexpr uint32_t kDramPaBase     = 0x0C000000u;

constexpr uint16_t kLcdBiasOn        = 0x0002u;
constexpr uint16_t kLcdOn            = 0x0004u;
constexpr uint16_t kLcdDisplayEnable = 0x0008u;

constexpr uint32_t kGrayscaleBgra[4] = {
    0xFF000000u,  /* level 0: black  (0x00) */
    0xFF555555u,  /* level 1: dark   (0x55) */
    0xFFAAAAAAu,  /* level 2: light  (0xAA) */
    0xFFFFFFFFu,  /* level 3: white  (0xFF) */
};

class OdoArm720DisplayRegs : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::OdoArm720;
    }
    void OnReady() override {
        /* Poseidon FPGA populates DISP_XSIZE / DISP_YSIZE at silicon
           reset with (size-1) for the attached panel; EBOOT reads them
           with the +1 convention (OEMBOOT.C:93-94). Odo carries a
           480x240 panel — see DISPDRVR.C:51-52 cxScreen/cyScreen. */
        xsize_ = 479;
        ysize_ = 239;
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kDisplayRegsPa; }
    uint32_t MmioSize() const override { return kDisplayRegsSize; }

    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        uint16_t value;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            if      (off == kSlotDispCsr)   value = csr_;
            else if (off == kSlotDispXSize) value = xsize_;
            else if (off == kSlotDispYSize) value = ysize_;
            else HaltUnsupportedAccess("ReadHalf", addr, 0);
        }
#if CERF_DEV_MODE
        LOG(Lcd, "Odo DISP read  +0x%02X -> 0x%04X\n", off, value);
#endif
        return value;
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        const uint32_t off = addr - MmioBase();
#if CERF_DEV_MODE
        LOG(Lcd, "Odo DISP write +0x%02X = 0x%04X\n", off, value);
#endif
        uint32_t panel_w     = 0;
        uint32_t panel_h     = 0;
        bool     fire_enabled = false;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            if (off == kSlotDispCsr) {
                const uint16_t old = csr_;
                csr_ = value;
                if (((old & kLcdOn) == 0u) && ((value & kLcdOn) != 0u)) {
                    fire_enabled = true;
                    panel_w = (uint32_t)xsize_ + 1u;
                    panel_h = (uint32_t)ysize_ + 1u;
                }
            }
            else if (off == kSlotDispXSize) xsize_ = value;
            else if (off == kSlotDispYSize) ysize_ = value;
            else HaltUnsupportedAccess("WriteHalf", addr, value);
        }
        if (fire_enabled) {
            emu_.Get<HostWindow>().OnLcdEnabled(panel_w, panel_h);
        }
    }

    uint16_t Csr   () const { std::lock_guard<std::mutex> lk(state_mutex_); return csr_;   }
    uint32_t XSize () const { std::lock_guard<std::mutex> lk(state_mutex_); return (uint32_t)xsize_ + 1u; }
    uint32_t YSize () const { std::lock_guard<std::mutex> lk(state_mutex_); return (uint32_t)ysize_ + 1u; }

private:
    mutable std::mutex state_mutex_;
    uint16_t csr_   = 0;
    uint16_t xsize_ = 0;
    uint16_t ysize_ = 0;
};

class OdoArm720DisplayDma : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::OdoArm720;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kDispDmaPa; }
    uint32_t MmioSize() const override { return kDispDmaSize; }

    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        uint16_t value;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            if      (off == kSlotDmaLow)  value = dma_low_;
            else if (off == kSlotDmaHigh) value = dma_high_;
            else HaltUnsupportedAccess("ReadHalf", addr, 0);
        }
#if CERF_DEV_MODE
        LOG(Lcd, "Odo DISP_DMA read  +0x%02X -> 0x%04X\n", off, value);
#endif
        return value;
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        const uint32_t off = addr - MmioBase();
#if CERF_DEV_MODE
        LOG(Lcd, "Odo DISP_DMA write +0x%02X = 0x%04X\n", off, value);
#endif
        std::lock_guard<std::mutex> lk(state_mutex_);
        if      (off == kSlotDmaLow)  dma_low_  = value;
        else if (off == kSlotDmaHigh) dma_high_ = value;
        else HaltUnsupportedAccess("WriteHalf", addr, value);
    }

    uint32_t GetEffectivePa() {
        std::lock_guard<std::mutex> lk(state_mutex_);
        const uint32_t chip_addr =
            (static_cast<uint32_t>(dma_high_ & 0xFFu) << 16) |
            static_cast<uint32_t>(dma_low_);
        return kDramPaBase + chip_addr;
    }

private:
    mutable std::mutex state_mutex_;
    uint16_t dma_low_  = 0;
    uint16_t dma_high_ = 0;
};

class OdoArm720LcdRenderer : public FrameRenderer {
public:
    using FrameRenderer::FrameRenderer;

    bool ShouldRegister() override {
        if (emu_.Get<DeviceConfig>().guest_additions) return false;
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::OdoArm720;
    }

    bool HasFrame() override {
        auto& regs = emu_.Get<OdoArm720DisplayRegs>();
        if ((regs.Csr() & kLcdOn) == 0) return false;
        if (latch_.Latched()) return true;
        const uint32_t xs = regs.XSize();
        const uint32_t ys = regs.YSize();
        if (xs == 0 || ys == 0) return false;
        return latch_.ProbeAndLatch(emu_.Get<EmulatedMemory>(),
                                    emu_.Get<OdoArm720DisplayDma>()
                                       .GetEffectivePa(),
                                    (size_t)(xs * ys) / 4u,
                                    251u);
    }

    void RenderInto(uint32_t* dib_bgra32,
                    uint32_t  width,
                    uint32_t  height) override {
        auto& mem  = emu_.Get<EmulatedMemory>();
        auto& regs = emu_.Get<OdoArm720DisplayRegs>();
        const uint32_t fb_pa = emu_.Get<OdoArm720DisplayDma>()
                                  .GetEffectivePa();
        const uint32_t guest_w = regs.XSize();
        const uint32_t guest_h = regs.YSize();
        if (guest_w == 0 || guest_h == 0) return;
        const uint32_t bytes_per_row = guest_w / 4u;

        for (uint32_t y = 0; y < height; ++y) {
            const uint32_t src_y = (y * guest_h) / height;
            const uint32_t row_pa = fb_pa + src_y * bytes_per_row;
            uint32_t* dst_row = dib_bgra32 + y * width;
            for (uint32_t x = 0; x < width; ++x) {
                const uint32_t src_x = (x * guest_w) / width;
                const uint32_t byte_off = src_x >> 2;        /* 4 px / byte */
                const uint32_t shift    = (3u - (src_x & 3u)) * 2u;
                const uint8_t  b        = mem.ReadByte(row_pa + byte_off);
                const uint32_t level    = (b >> shift) & 0x3u;
                dst_row[x] = kGrayscaleBgra[level];
            }
        }
    }

    std::optional<FbLayout> GetFbLayout() override {
        auto& regs = emu_.Get<OdoArm720DisplayRegs>();
        const uint32_t w = regs.XSize();
        if (w == 0) return std::nullopt;
        /* 2-bpp packed grayscale, 4 px/byte (same packing RenderInto unpacks),
           so the row pitch is w/4 bytes. */
        return FbLayout{ emu_.Get<OdoArm720DisplayDma>().GetEffectivePa(),
                         w / 4u, 2u, false };
    }

private:
    LcdContentLatch latch_;
};

}  /* namespace */

REGISTER_SERVICE   (OdoArm720DisplayRegs);
REGISTER_SERVICE   (OdoArm720DisplayDma);
REGISTER_SERVICE_AS(OdoArm720LcdRenderer, FrameRenderer);
