#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "msm8255_id.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../irq_controller.h"
#include "../guest_cpu_reset.h"

#include <atomic>
#include <cstdint>

namespace {

constexpr uint32_t kMdpBase = 0xA3F00000u;
constexpr uint32_t kMdpSize = 0x00100000u;

constexpr uint32_t kWordCount = kMdpSize / 4u;

/* Linux arch/arm/mach-msm video-msm mdp.c mdp_probe reads the word at the MDP
   base as mdp_version and tests it against the packed 0x04030303, one byte per
   version field. */
constexpr uint32_t kRegVersion   = 0x00000u;
constexpr uint32_t kVersionValue = 0x04000000u;

/* Linux arch/arm/mach-msm video-msm mdp.h, the CONFIG_FB_MSM_MDP40 arm:
   MDP_EBI2_PORTMAP_MODE. */
constexpr uint32_t kRegEbi2PortmapMode = 0x00070u;

/* Linux arch/arm/mach-msm video-msm mdp.h, the CONFIG_FB_MSM_MDP40 arm:
   MDP_INTR_ENABLE, MDP_INTR_STATUS and MDP_INTR_CLEAR. */
constexpr uint32_t kRegIntrEnable = 0x00050u;
constexpr uint32_t kRegIntrStatus = 0x00054u;
constexpr uint32_t kRegIntrClear  = 0x00058u;

/* Linux arch/arm/mach-msm video-msm mdp4_util.c mdp4_display_status reads
   MDP_DISPLAY_STATUS and keeps its low ten bits. */
constexpr uint32_t kRegDispStatus = 0x00018u;

/* Linux drivers/gpu/drm/msm registers display mdp4.xml: DISP_INTF_SEL, whose
   PRIM and EXT fields mdp4_overlay.c reads back per mixer. */
constexpr uint32_t kRegDispIntfSel = 0x00038u;

/* Linux drivers/gpu/drm/msm registers display mdp4.xml: the DMA array's CONFIG
   register, bit 24 of which it names DITHER_EN on DMA_P. */
constexpr uint32_t kRegDmaPConfig = 0x90000u;

/* Linux drivers/gpu/drm/msm registers display mdp4.xml: the DMA array's second
   element, which its mdp4_dma index names DMA_S. */
constexpr uint32_t kDmaSBase = 0xA0000u;

/* Linux arch/arm/mach-msm video-msm mdp_vsync.c: MDP_VSYNC_SEL. */
constexpr uint32_t kRegVsyncSel = 0x00124u;

/* Linux drivers/gpu/drm/msm registers display mdp4.xml: the LCDC array's
   ENABLE register, whose bit 0 mdp4_util.c tests before clearing the block. */
constexpr uint32_t kRegLcdcEnable = 0xC0000u;

/* Linux arch/arm/mach-msm video-msm mdp_vsync.c, its CONFIG_FB_MSM_MDP40 arm:
   MDP_SYNC_CFG_0 and MDP_SYNC_CFG_1, which mdp_set_sync_cfg_0 and _1 build from
   the line count, the external-vsync enable and the vsync counter. */
constexpr uint32_t kRegSyncCfg0 = 0x00100u;
constexpr uint32_t kRegSyncCfg1 = 0x00104u;

constexpr uint32_t kReg020C = 0x0020Cu;

/* Linux arch/arm/mach-msm irqs-7x30.h: INT_MDP. */
constexpr uint32_t kVicLine = 80u;

/* Linux arch/arm/mach-msm video-msm mdp4.h: MDP4_OVERLAYPROC0_BASE and
   MDP4_OVERLAYPROC1_BASE. */
constexpr uint32_t kOverlayProc0 = 0x10000u;
constexpr uint32_t kOverlayProc1 = 0x18000u;

/* Linux arch/arm/mach-msm video-msm mdp4_overlay.c reads the overlay
   processor's word at +0x14 and writes it back with GC_LUT_EN set. */
constexpr uint32_t kRegOverlayOp0 = kOverlayProc0 + 0x14u;
constexpr uint32_t kRegOverlayOp1 = kOverlayProc1 + 0x14u;

/* Linux drivers/gpu/drm/msm registers display mdp4.xml: the OVLP array names
   the register at +0x04 CFG, and mdp4_overlay.c writes it 0x01 for direct
   output. */
constexpr uint32_t kRegOverlayCfg0 = kOverlayProc0 + 0x04u;

/* Linux drivers/gpu/drm/msm registers display mdp4.xml: LAYERMIXER_IN_CFG, a
   top-level register whose mdp4_layermixer_in_cfg type gives each pipe a
   three-bit stage id and a mixer-one bit. */
constexpr uint32_t kRegLayermixerInCfg = 0x10100u;

/* Linux drivers/gpu/drm/msm registers display mdp4.xml: OVERLAY_FLUSH, one
   boolean per block in the order OVLP0, OVLP1, VG1, VG2, RGB1, RGB2. */
constexpr uint32_t kRegOverlayFlush = 0x18000u;

/* Linux drivers/gpu/drm/msm registers display mdp4.xml: OVLP0_KICK, the first
   of the per-block kick registers. */
constexpr uint32_t kRegOvlp0Kick = 0x00004u;

/* Linux arch/arm/mach-msm video-msm mdp4.h: INTR_OVERLAY0_DONE, which
   mdp4_util.c mdp4_isr dispatches through its MDDI arm. */
constexpr uint32_t kIntrOverlay0Done = 0x00000001u;

/* Linux drivers/gpu/drm/msm registers display mdp4.xml: DMA_S_KICK. */
constexpr uint32_t kRegDmaSKick = 0x00010u;

/* Linux arch/arm/mach-msm video-msm mdp4.h: INTR_DMA_S_DONE, the bit
   mdp4_util.c mdp4_isr completes the DMA_S block on. */
constexpr uint32_t kIntrDmaSDone = 0x00000004u;

struct KickDone {
    uint32_t kick;
    uint32_t done;
};

constexpr KickDone kKickDone[] = {
    {kRegOvlp0Kick, kIntrOverlay0Done},
    {kRegDmaSKick, kIntrDmaSDone},
};

/* Linux arch/arm/mach-msm video-msm mdp4.h: MDP4_RGB_BASE and MDP4_RGB_OFF. */
constexpr uint32_t kRgbBase = 0x40000u;
constexpr uint32_t kRgbOff  = 0x10000u;

/* Linux arch/arm/mach-msm video-msm mdp4_overlay.c mdp4_overlay_rgb_setup
   programs one pipe from rgb_base and reads MDP_RGB_OP_MODE back to carry the
   bit its own write mask excludes. */
constexpr uint32_t kRgbPipeBase  = kRgbBase + kRgbOff;
constexpr uint32_t kRegRgbOpMode = kRgbPipeBase + 0x58u;

constexpr uint32_t kRegReset = 0u;

constexpr uint32_t kStateChunkWords = 1024u;
static_assert(kWordCount % kStateChunkWords == 0u,
              "the register file must divide into whole state chunks");

struct Span {
    uint32_t first;
    uint32_t last;
};

constexpr Span kWritableSpans[] = {
    {0x00028u, 0x00028u}, {0x00030u, 0x00030u},
    {kRegDispIntfSel, kRegDispIntfSel}, {0x00048u, 0x00048u},
    {0x00060u, 0x00060u}, {0x00068u, 0x00068u},
    {0x00070u, 0x00070u}, {0x00090u, 0x00090u}, {0x00094u, 0x00094u},
    {0x00098u, 0x00098u},
    {kRegSyncCfg0, kRegSyncCfg0}, {kRegSyncCfg1, kRegSyncCfg1},
    {0x00118u, 0x00118u}, {0x0011Cu, 0x0011Cu}, {kRegVsyncSel, kRegVsyncSel},
    {0x00200u, 0x00200u}, {0x00204u, 0x00204u},
    {kReg020C, kReg020C}, {0x00210u, 0x00210u}, {0x00214u, 0x00214u},
    {0x0021Cu, 0x0021Cu}, {0x00220u, 0x00220u},
    {kRegOverlayCfg0, kRegOverlayCfg0},
    {kOverlayProc0 + 0x08u, kOverlayProc0 + 0x10u},
    {kRegOverlayOp0, kRegOverlayOp0}, {kRegOverlayOp1, kRegOverlayOp1},
    {kRegLayermixerInCfg, kRegLayermixerInCfg},
    {kRegOverlayFlush, kRegOverlayFlush},
    {kRgbPipeBase + 0x00u, kRgbPipeBase + 0x0Cu},
    {kRgbPipeBase + 0x10u, kRgbPipeBase + 0x10u},
    {kRgbPipeBase + 0x40u, kRgbPipeBase + 0x40u},
    {kRgbPipeBase + 0x50u, kRgbPipeBase + 0x60u},
    {0x11004u, 0x11004u}, {0x21004u, 0x21004u}, {0x31004u, 0x31004u},
    {0x41004u, 0x41004u}, {0x51004u, 0x51004u}, {0x91004u, 0x91004u},
    {0x24400u, 0x24420u}, {0x24500u, 0x24508u}, {0x24580u, 0x24588u},
    {0x24600u, 0x24614u}, {0x24680u, 0x24694u},
    {0x28100u, 0x2810Cu}, {0x28200u, 0x28204u}, {0x29000u, 0x2AFFCu},
    {0x34400u, 0x34420u}, {0x34500u, 0x34508u}, {0x34580u, 0x34588u},
    {0x34600u, 0x34614u}, {0x34680u, 0x34694u},
    {0x38100u, 0x3810Cu}, {0x38200u, 0x38204u}, {0x39000u, 0x3AFFCu},
    {0x90000u, 0x90010u}, {0x90018u, 0x90020u}, {0x90040u, 0x9004Cu},
    {0x90060u, 0x90070u},
    {kDmaSBase, kDmaSBase + 0x10u},
    {kDmaSBase + 0x18u, kDmaSBase + 0x18u},
    {0x93400u, 0x93420u}, {0x93500u, 0x93508u}, {0x93580u, 0x93588u},
    {0x93600u, 0x93614u}, {0x93680u, 0x93694u},
    {0x94800u, 0x94FFCu},
    {0x95004u, 0x95008u}, {0x95010u, 0x95010u}, {0x95018u, 0x9501Cu},
    {0xC0000u, 0xC0038u}, {0xC2000u, 0xC2010u},
};

class Msm8255Mdp : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == SocId::Msm8255;
    }

    void OnReady() override {
        ResetState();
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            ResetState();
            PublishLine();
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kMdpBase; }
    uint32_t MmioSize() const override { return kMdpSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (off == kRegVersion) {
            return kVersionValue;
        }
        if (off == kRegIntrEnable || off == kRegIntrStatus ||
            off == kRegDispStatus || off == kRegDispIntfSel ||
            off == kRegDmaPConfig || off == kDmaSBase ||
            off == kRegVsyncSel || off == kRegLcdcEnable ||
            off == kRegEbi2PortmapMode ||
            off == kRegSyncCfg0 || off == kRegSyncCfg1 || off == kReg020C ||
            off == kRegOverlayOp0 || off == kRegOverlayOp1 ||
            off == kRegLayermixerInCfg || off == kRegRgbOpMode) {
            return Reg(off);
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        if (off == kRegIntrEnable) {
            SetReg(kRegIntrEnable, value);
            PublishLine();
            return;
        }
        /* Linux arch/arm/mach-msm video-msm mdp4_util.c mdp4_isr writes the
           status word it has just read to MDP_INTR_CLEAR, so a set bit clears
           that source. */
        if (off == kRegIntrClear) {
            SetReg(kRegIntrStatus, Reg(kRegIntrStatus) & ~value);
            PublishLine();
            return;
        }
        for (const KickDone& k : kKickDone) {
            if (off != k.kick) continue;
            SetReg(kRegIntrStatus, Reg(kRegIntrStatus) | k.done);
            PublishLine();
            return;
        }
        if (!IsWritable(off)) {
            HaltUnsupportedAccess("WriteWord", addr, value);
        }
        SetReg(off, value);
    }

    void SaveState(StateWriter& w) override {
        uint32_t chunk[kStateChunkWords];
        for (uint32_t base = 0; base < kWordCount; base += kStateChunkWords) {
            for (uint32_t i = 0; i < kStateChunkWords; ++i) {
                chunk[i] = regs_[base + i].load(std::memory_order_acquire);
            }
            w.WriteBytes("chunk", chunk, sizeof(chunk));
        }
    }

    void RestoreState(StateReader& r) override {
        uint32_t chunk[kStateChunkWords];
        for (uint32_t base = 0; base < kWordCount; base += kStateChunkWords) {
            r.ReadBytes("chunk", chunk, sizeof(chunk));
            for (uint32_t i = 0; i < kStateChunkWords; ++i) {
                regs_[base + i].store(chunk[i], std::memory_order_release);
            }
        }
    }

    void PostRestore() override { PublishLine(); }

private:
    uint32_t Reg(uint32_t off) const {
        return regs_[off / 4u].load(std::memory_order_acquire);
    }

    /* Linux arch/arm/mach-msm video-msm mdp4_util.c mdp4_isr takes the pending
       set as MDP_INTR_STATUS masked by MDP_INTR_ENABLE, so the line follows
       that product. */
    void PublishLine() {
        auto& vic = emu_.Get<IrqController>();
        if ((Reg(kRegIntrStatus) & Reg(kRegIntrEnable)) != 0u) {
            vic.AssertIrq(kVicLine);
        } else {
            vic.DeAssertIrq(kVicLine);
        }
    }

    void SetReg(uint32_t off, uint32_t value) {
        regs_[off / 4u].store(value, std::memory_order_release);
    }

    void ResetState() {
        for (uint32_t i = 0; i < kWordCount; ++i) {
            regs_[i].store(kRegReset, std::memory_order_release);
        }
    }

    static bool IsWritable(uint32_t off) {
        for (const Span& s : kWritableSpans) {
            if (off >= s.first && off <= s.last) return true;
        }
        return false;
    }

    std::atomic<uint32_t> regs_[kWordCount] = {};
};

}

REGISTER_SERVICE(Msm8255Mdp);
